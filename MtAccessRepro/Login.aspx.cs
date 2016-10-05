using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
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
        private const string AuthorityEndpoint = "https://login.windows.net/";
        private const string CommonTenantId = "common";
        private const string ClientId = "...";
        private const string ClientSecret = "...";
        private const string TenantId = "...";

        private static async Task<AuthenticationResult> GetTokenFromAuthCodeAsync(string authCode, Uri replyUrl)
        {
            var clientCredential = new ClientCredential(ClientId, ClientSecret);
            var context = new AuthenticationContext($"{AuthorityEndpoint}{CommonTenantId}");
            return await context.AcquireTokenByAuthorizationCodeAsync(authCode, replyUrl, clientCredential, ManagementEndpoint);
        }

        private static async Task<AuthenticationResult> GetTokenForAppAsync(string resourceId)
        {
            var clientCredential = new ClientCredential(ClientId, ClientSecret);
            var context = new AuthenticationContext($"{AuthorityEndpoint}{resourceId}");
            return await context.AcquireTokenAsync(ManagementEndpoint, clientCredential);
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

        private static async Task<string> AddRoleAssignmentAsync(AuthenticationResult token, string subscriptionId)
        {
            var authorizationClient = new AuthorizationManagementClient(new TokenCredentials(token.AccessToken))
            {
                SubscriptionId = subscriptionId
            };

            // Question 5a: How do you get the principal id? I'm pulling it from the app only bearer token now, no idea if that's correct
            var appToken = await GetTokenForAppAsync(TenantId); // how do I get the resourceId here? This is the tenantId in the app's Azure subscription
            var jwtToken = new JwtSecurityToken(appToken.AccessToken);
            var principalId = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "oid")?.Value;

            var existingAssignments = await authorizationClient.RoleAssignments.ListAsync(new ODataQuery<RoleAssignmentFilter>(filter => filter.PrincipalId == principalId));
            if (existingAssignments.Any())
            {
                return "Already existed: " + existingAssignments.First().Name;
            }

            var roleAssignmentId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"; // Owner role. Todo, create a new role with precisely the permissions we require

            var roleAssignmentName = Guid.NewGuid().ToString();
            var roleAssignment = await authorizationClient.RoleDefinitions.GetAsync($"/subscriptions/{subscriptionId}", roleAssignmentId);
            var newAssignment = await authorizationClient.RoleAssignments.CreateAsync($"/subscriptions/{subscriptionId}", roleAssignmentName, new RoleAssignmentProperties
            {
                PrincipalId = principalId,
                RoleDefinitionId = roleAssignment.Id
            });
            return roleAssignmentName;
        }

        private string authCode, replyUrl;
        protected void Page_Load(object sender, EventArgs e)
        {
            ClientIdLabel.InnerText = ClientId;
            var queries = HttpUtility.ParseQueryString(ClientQueryString);
            if (!queries.HasKeys())
            {
                return; // not logged in yet
            }

            // Step 2: Get the AuthCode
            authCode = queries["code"];
            replyUrl = HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path);

            if (!IsPostBack)
            {
                RegisterAsyncTask(new PageAsyncTask(PopulateSubscriptionsAsync));
            }
            if (SubscriptionsElement.SelectedIndex != 0)
            {
                RegisterAsyncTask(new PageAsyncTask(GetSubscriptionDisplayNameAsync));
            }
        }

        private async Task PopulateSubscriptionsAsync()
        {
            // Step 3: Get the bearer token
            var token = await GetTokenFromAuthCodeAsync(authCode, new Uri(replyUrl));

            // Step 4: Enumerate subscriptions
            var subscriptions = await GetSubscriptionIdsAsync(token);
            SubscriptionsElement.Items.AddRange(subscriptions.Select(s => new ListItem
            {
                Text = s
            }).ToArray());
        }

        private async Task AddRoleAssignmentAsync()
        {
            var subscriptionId = SubscriptionsElement.Items[SubscriptionsElement.SelectedIndex].Text;
            var token = await GetTokenFromAuthCodeAsync(authCode, new Uri(replyUrl));

            // Step 5: Add a role assignment for our application in this subscriptions
            var roleDefinitionName = await AddRoleAssignmentAsync(token, subscriptionId);
            DefinitionId.InnerText = roleDefinitionName;
        }

        private async Task GetSubscriptionDisplayNameAsync()
        {
            var subscriptionId = SubscriptionsElement.Items[SubscriptionsElement.SelectedIndex].Text;
            var appToken = await GetTokenForAppAsync(TenantId); // Question 6a: Not sure if TenantId is correct here
            string displayName;
            try
            {
                // Step 6: Try to get some properties of the subscription
                displayName = await GetSubscriptionDisplayNameAsync(appToken, subscriptionId);
            }
            catch
            {
                displayName = "Could not get subscription name";
            }

            SubscriptionName.InnerText = displayName;
        }

        protected void LinkButton_OnServerClick(object sender, EventArgs e)
        {
            if (SubscriptionsElement.SelectedIndex == 0)
            {
                return; // default element selected
            }

            RegisterAsyncTask(new PageAsyncTask(AddRoleAssignmentAsync));
        }
    }
}