# One-time setup

The pipeline signs in to Azure with OIDC (no stored secrets) using two app registrations,
so the identity that runs on every PR can never write to production.

## 1. Azure app registrations

| App | Federated credential (GitHub) | Roles |
|---|---|---|
| `sentinel-ci-pr` | Entity: **Pull request**. Add a second one for branch `main` (used by the export workflow). | **Log Analytics Reader** and **Microsoft Sentinel Reader** on the prod workspace; **Microsoft Sentinel Contributor** on the test workspace's resource group |
| `sentinel-ci-deploy` | Entity: **Environment**, name `production` | **Microsoft Sentinel Contributor** on the prod workspace's resource group |

For each: Entra ID > App registrations > New, then Certificates & secrets > Federated
credentials > Add > "GitHub Actions deploying Azure resources", with your org, repo and
the entity above. Assign roles under the resource group's Access control (IAM).

If a deploy fails with an authorization error on `Microsoft.Resources/deployments`,
add **Contributor** scoped to that resource group only.

## 2. Test workspace

A separate Log Analytics workspace with Microsoft Sentinel enabled. It doesn't need log
data: the read-only checks run against prod, and the test workspace confirms that each
rule deploys and schedules cleanly.

## 3. GitHub repository settings

**Settings > Secrets and variables > Actions > Variables:**

| Variable | Value |
|---|---|
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription holding the workspaces |
| `AZURE_CLIENT_ID_PR` | Client ID of `sentinel-ci-pr` |
| `AZURE_CLIENT_ID_DEPLOY` | Client ID of `sentinel-ci-deploy` |
| `PROD_WORKSPACE_ID` | Prod workspace ID (GUID, from the workspace Overview page) |
| `PROD_WORKSPACE_NAME` | Prod workspace name |
| `PROD_RESOURCE_GROUP` | Prod workspace resource group |
| `TEST_WORKSPACE_NAME` | Test workspace name |
| `TEST_RESOURCE_GROUP` | Test workspace resource group |

**Settings > Environments > New environment** named `production`, with yourself as a
required reviewer.

**Settings > Branches:** protect `main` and require the **PR checks** jobs to pass.

## 4. Export the existing rules

Actions > **Export existing rules** > Run workflow. The rules land on the
`exported-rules` branch under `rules/exported/`.
