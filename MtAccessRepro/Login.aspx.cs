using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Azure.Management.Authorization;
using Microsoft.Azure.Management.Authorization.Models;
using Microsoft.Azure.Management.ResourceManager;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest;
using Microsoft.Rest.Azure.OData;

namespace MtAccessRepro
{
    public partial class Login : Page
    {
        private const string ManagementEndpoint = "https://management.azure.com/";
        private const string GraphEndpointFormat = "https://login.microsoftonline.com/";
        private const string GraphResource = "https://graph.windows.net/";
        private const string AuthorityEndpoint = "https://login.windows.net/";
        private const string CommonTenantId = "common";
        private const string ClientId = "...";
        private const string ClientSecret = "...";

        private static async Task<string> GetAuthorityForSubscription(string subscriptionId)
        {
            string url = $"{ManagementEndpoint}/subscriptions/{subscriptionId}?api-version=2014-04-01";
            using (var client = new HttpClient())
            {
                var response = await client.GetAsync(url);
                var authenticationParameters = await AuthenticationParameters.CreateFromUnauthorizedResponseAsync(response);
                return authenticationParameters.Authority;
            }
        }

        private static async Task<string> GetDirectoryForSubscription(string subscriptionId)
        {
            var authority = new Uri(await GetAuthorityForSubscription(subscriptionId));
            return authority.Segments.LastOrDefault();
        }

        private static async Task<AuthenticationResult> GetTokenFromAuthCodeAsync(string authCode, Uri replyUrl)
        {
            var clientCredential = new ClientCredential(ClientId, ClientSecret);
            var context = new AuthenticationContext($"{AuthorityEndpoint}{CommonTenantId}");
            return await context.AcquireTokenByAuthorizationCodeAsync(authCode, replyUrl, clientCredential, ManagementEndpoint);
        }

        private static async Task<AuthenticationResult> GetTokenForAppAsync(string subscriptionId)
        {
            var clientCredential = new ClientCredential(ClientId, ClientSecret);
            var context = new AuthenticationContext(await GetAuthorityForSubscription(subscriptionId));
            return await context.AcquireTokenAsync(ManagementEndpoint, clientCredential);
        }

        private static async Task<AuthenticationResult> GetTokenForGraphAsync(string subscriptionId)
        {
            var clientCredential = new ClientCredential(ClientId, ClientSecret);
            var context = new AuthenticationContext(GraphEndpointFormat + await GetDirectoryForSubscription(subscriptionId));
            return await context.AcquireTokenAsync(GraphResource, clientCredential);
        }

        private static async Task<IEnumerable<string>> GetSubscriptionIdsAsync(AuthenticationResult token)
        {
            var subscriptionClient = new SubscriptionClient(new TokenCredentials(token.AccessToken));
            var subscriptions = await subscriptionClient.Subscriptions.ListAsync();
            return subscriptions.Select(s => s.SubscriptionId);
        }

        private static async Task<string> GetSubscriptionDisplayNameAsync(AuthenticationResult token, string subscriptionId)
        {
            var subscriptionClient = new SubscriptionClient(new TokenCredentials(token.AccessToken));
            var subscription = await subscriptionClient.Subscriptions.GetAsync(subscriptionId);
            return subscription.DisplayName;
        }

        private static async Task<string> GetPrincipalIdProper(string subscriptionId)
        {
            //var token = await GetTokenForGraphAsync(subscriptionId);
            var client = new ActiveDirectoryClient(new Uri(GraphResource + await GetDirectoryForSubscription(subscriptionId)),
                async () => (await GetTokenForGraphAsync(subscriptionId)).AccessToken);
            var principal = await client.ServicePrincipals.Where(service => service.AppId == ClientId).ExecuteSingleAsync();
            return principal.ObjectId;
        }

        private static async Task<string> GetPrincipalId(string subscriptionId)
        {
            var properPrincipal = await GetPrincipalIdProper(subscriptionId);

            // Question 5a: How do you get the principal id? I'm pulling it from the app only bearer token now, no idea if that's correct
            var appToken = await GetTokenForAppAsync(subscriptionId);
            var jwtToken = new JwtSecurityToken(appToken.AccessToken);
            var hackyPrincipal = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "oid")?.Value;

            if (properPrincipal != hackyPrincipal)
            {
                throw new Exception("Principals disagree!");
            }

            return properPrincipal;
        }

        private static async Task<string> AddRoleAssignmentAsync(AuthenticationResult token, string subscriptionId)
        {
            var authorizationClient = new AuthorizationManagementClient(new TokenCredentials(token.AccessToken))
            {
                SubscriptionId = subscriptionId
            };

            var principalId = await GetPrincipalId(subscriptionId);

            var existingAssignments = await authorizationClient.RoleAssignments.ListAsync(new ODataQuery<RoleAssignmentFilter>(filter => filter.PrincipalId == principalId));
            if (existingAssignments.Any())
            {
                return "Already existed: " + existingAssignments.First().Name;
            }

            var roleAssignmentId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"; // Owner role. Todo, create a new role with precisely the permissions we require

            var roleAssignment = await authorizationClient.RoleDefinitions.GetAsync($"/subscriptions/{subscriptionId}", roleAssignmentId);
            var newAssignment = await authorizationClient.RoleAssignments.CreateAsync($"/subscriptions/{subscriptionId}", Guid.NewGuid().ToString(), new RoleAssignmentProperties
            {
                PrincipalId = principalId,
                RoleDefinitionId = roleAssignment.Id
            });
            return newAssignment.Name;
        }

        private static async Task<string> RemoveRoleAssignmentAsync(AuthenticationResult token, string subscriptionId)
        {
            var authorizationClient = new AuthorizationManagementClient(new TokenCredentials(token.AccessToken))
            {
                SubscriptionId = subscriptionId
            };

            var principalId = await GetPrincipalId(subscriptionId);

            var existingAssignments = await authorizationClient.RoleAssignments.ListAsync(new ODataQuery<RoleAssignmentFilter>(filter => filter.PrincipalId == principalId));
            if (!existingAssignments.Any())
            {
                return "No existing role assignment";
            }

            var deletedAssignment = await authorizationClient.RoleAssignments.DeleteByIdAsync(existingAssignments.First().Id);
            return deletedAssignment.Name;
        }

        private string _authCode, _replyUrl;
        protected void Page_Load(object sender, EventArgs e)
        {
            ClientIdLabel.InnerText = ClientId;
            var queries = HttpUtility.ParseQueryString(ClientQueryString);
            if (!queries.HasKeys())
            {
                return; // not logged in yet
            }

            // Step 2: Get the AuthCode
            _authCode = queries["code"];
            _replyUrl = HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path);

            if (!IsPostBack)
            {
                RegisterAsyncTask(new PageAsyncTask(PopulateSubscriptionsAsync));
            }
        }

        private async Task PopulateSubscriptionsAsync()
        {
            // Step 3: Get the bearer token
            var token = await GetTokenFromAuthCodeAsync(_authCode, new Uri(_replyUrl));

            // Step 4: Enumerate subscriptions
            var subscriptions = await GetSubscriptionIdsAsync(token);
            SubscriptionsElement.Items.AddRange(subscriptions.Select(s => new ListItem
            {
                Text = s
            }).ToArray());
        }

        private async Task PopulateSubscriptionDisplayNameAsync(string subscriptionId)
        {
            string displayName;
            var appToken = await GetTokenForAppAsync(subscriptionId);
            try
            {
                // Step 6: Try to get some properties of the subscription using the app only token
                displayName = await GetSubscriptionDisplayNameAsync(appToken, subscriptionId);
            }
            catch
            {
                displayName = "Could not get subscription name";
            }
            SubscriptionName.InnerText = displayName;
        }

        private async Task AddRoleAssignmentAsync()
        {
            var subscriptionId = SubscriptionsElement.Items[SubscriptionsElement.SelectedIndex].Text;
            var token = await GetTokenFromAuthCodeAsync(_authCode, new Uri(_replyUrl));

            // Step 5: Add a role assignment for our application in this subscriptions
            var roleDefinitionName = await AddRoleAssignmentAsync(token, subscriptionId);
            DefinitionId.InnerText = roleDefinitionName;

            await PopulateSubscriptionDisplayNameAsync(subscriptionId);
        }

        protected void LinkButton_OnServerClick(object sender, EventArgs e)
        {
            if (SubscriptionsElement.SelectedIndex == 0)
            {
                return; // default element selected
            }

            RegisterAsyncTask(new PageAsyncTask(AddRoleAssignmentAsync));
        }

        private async Task RemoveRoleAssignmentAsync()
        {
            var subscriptionId = SubscriptionsElement.Items[SubscriptionsElement.SelectedIndex].Text;
            var token = await GetTokenFromAuthCodeAsync(_authCode, new Uri(_replyUrl));

            // Step 5: Add a role assignment for our application in this subscriptions
            var roleDefinitionName = await RemoveRoleAssignmentAsync(token, subscriptionId);
            DefinitionId.InnerText = "Removed " + roleDefinitionName;

            await PopulateSubscriptionDisplayNameAsync(subscriptionId);
        }

        protected void UnlinkButton_OnServerClick(object sender, EventArgs e)
        {
            if (SubscriptionsElement.SelectedIndex == 0)
            {
                return; // default element selected
            }

            RegisterAsyncTask(new PageAsyncTask(RemoveRoleAssignmentAsync));
        }
    }
}