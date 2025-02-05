package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
)

type AssumeRolePolicyDocument struct {
	Statement []struct {
		Principal struct {
			Service string `json:"Service"`
			Aws     string `json:"AWS"`
		} `json:"Principal"`
		Action    []string `json:"Action"`
		Condition struct {
			StringEquals    map[string]string   `json:"StringEquals,omitempty"`
			StringNotEquals map[string][]string `json:"StringNotEquals,omitempty"`
			Null            map[string]string   `json:"Null,omitempty"`
			Bool            map[string]bool     `json:"Bool,omitempty"` // Added Bool for new condition
			ArnLike         map[string][]string `json:"ArnLike,omitempty"`
			StringLike      map[string][]string `json:"StringLike,omitempty"`
		} `json:"Condition"`
	} `json:"Statement"`
}

func TestComponent(t *testing.T) {
	// Define the AWS region to use for the tests
	awsRegion := "us-east-2"

	// Initialize the test fixture
	fixture := helper.NewFixture(t, "../", awsRegion, "test/fixtures")

	// Ensure teardown is executed after the test
	defer fixture.TearDown()
	fixture.SetUp(&atmos.Options{})

	// Define the test suite
	fixture.Suite("default", func(t *testing.T, suite *helper.Suite) {
		// Test phase: Validate the functionality of the ALB component
		suite.Test(t, "basic", func(t *testing.T, atm *helper.Atmos) {
			inputs := map[string]interface{}{}
			defer atm.GetAndDestroy("aws-teams/basic", "default-test", inputs)
			component := atm.GetAndDeploy("aws-teams/basic", "default-test", inputs)
			assert.NotNil(t, component)

			rolesMap := atm.OutputMapOfObjects(component, "team_name_role_arn_map")
			assert.NotEmpty(t, rolesMap["admin"])
			assert.NotEmpty(t, rolesMap["viewer"])

			expectedNames := []string{
				strings.Split(rolesMap["admin"].(string), "/")[1],
				strings.Split(rolesMap["viewer"].(string), "/")[1],
			}
			names := atm.OutputList(component, "team_names")
			assert.ElementsMatch(t, expectedNames, names)

			expectedArns := []string{
				rolesMap["admin"].(string),
				rolesMap["viewer"].(string),
			}
			arns := atm.OutputList(component, "role_arns")
			assert.ElementsMatch(t, expectedArns, arns)

			config := atm.OutputMapOfObjects(component, "teams_config")
			adminRoleDescription := config["admin"].(map[string]interface{})["role_description"].(string)
			viewerRoleDescription := config["viewer"].(map[string]interface{})["role_description"].(string)

			assert.True(t, config["admin"].(map[string]interface{})["aws_saml_login_enabled"].(bool))
			assert.Equal(t, "viewer", config["admin"].(map[string]interface{})["denied_teams"].([]interface{})[0].(string))
			assert.Equal(t, float64(43200), config["admin"].(map[string]interface{})["max_session_duration"].(float64))
			assert.Equal(t, "Team with PowerUserAccess permissions in `identity` and AdministratorAccess to all other accounts except `root`", adminRoleDescription)
			assert.Equal(t, "arn:aws:iam::aws:policy/PowerUserAccess", config["admin"].(map[string]interface{})["role_policy_arns"].([]interface{})[0].(string))
			assert.Equal(t, "IdentityAdminTeamAccess", config["admin"].(map[string]interface{})["trusted_permission_sets"].([]interface{})[0].(string))
			assert.Equal(t, "admin", config["admin"].(map[string]interface{})["trusted_teams"].([]interface{})[0].(string))

			assert.False(t, config["viewer"].(map[string]interface{})["aws_saml_login_enabled"].(bool))
			assert.Equal(t, "viewer", config["viewer"].(map[string]interface{})["denied_teams"].([]interface{})[0].(string))
			assert.Equal(t, float64(43200), config["viewer"].(map[string]interface{})["max_session_duration"].(float64))
			assert.Equal(t, "Team restricted to viewing resources in the identity account", viewerRoleDescription)
			assert.Equal(t, "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", config["viewer"].(map[string]interface{})["role_policy_arns"].([]interface{})[0].(string))

			client := aws.NewIamClient(t, awsRegion)

			adminRoleName := strings.Split(rolesMap["admin"].(string), "/")[1]

			describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
				RoleName: &adminRoleName,
			})
			assert.NoError(t, err)

			awsRole := describeRoleOutput.Role
			assert.Equal(t, adminRoleName, *awsRole.RoleName)
			assert.Equal(t, adminRoleDescription, *awsRole.Description)

			assert.EqualValues(t, 43200, *awsRole.MaxSessionDuration)
			assert.Equal(t, "/", *awsRole.Path)

			assumeRolePolicyDocument, err := url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
			assert.NoError(t, err)

			var assumePolicyDoc AssumeRolePolicyDocument
			err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
			assert.NoError(t, err)

			assert.Contains(t, assumePolicyDoc.Statement[0].Principal.Aws, "root")
			assert.ElementsMatch(t, []string{
				"sts:AssumeRole",
				"sts:SetSourceIdentity",
				"sts:TagSession",
			}, assumePolicyDoc.Statement[0].Action)

			accountId := aws.GetAccountId(t)

			// Verify assume role conditions
			assert.NotNil(t, assumePolicyDoc.Statement[0].Condition)
			assert.Contains(t, assumePolicyDoc.Statement[0].Condition.ArnLike, "aws:PrincipalArn")
			assert.ElementsMatch(t, []string{
				fmt.Sprintf("arn:aws:iam::%s:role/tester-admin", accountId),
				fmt.Sprintf("arn:aws:iam::%s:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_IdentityAdminTeamAccess_*", accountId),
			},
				assumePolicyDoc.Statement[0].Condition.ArnLike["aws:PrincipalArn"])

			attachedPolicies, err := client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
				RoleName: &adminRoleName,
			})
			assert.NoError(t, err)

			expectedPolicies := []string{
				"arn:aws:iam::aws:policy/PowerUserAccess",
			}

			var actualPolicies []string
			for _, policy := range attachedPolicies.AttachedPolicies {
				actualPolicies = append(actualPolicies, *policy.PolicyArn)
			}

			assert.ElementsMatch(t, expectedPolicies, actualPolicies)

			viewerRoleName := strings.Split(rolesMap["viewer"].(string), "/")[1]

			describeRoleOutput, err = client.GetRole(context.Background(), &iam.GetRoleInput{
				RoleName: &viewerRoleName,
			})
			assert.NoError(t, err)

			awsRole = describeRoleOutput.Role
			assert.Equal(t, viewerRoleName, *awsRole.RoleName)
			assert.Equal(t, viewerRoleDescription, *awsRole.Description)

			assert.EqualValues(t, 43200, *awsRole.MaxSessionDuration)
			assert.Equal(t, "/", *awsRole.Path)

			assumeRolePolicyDocument, err = url.QueryUnescape(*awsRole.AssumeRolePolicyDocument)
			assert.NoError(t, err)

			err = json.Unmarshal([]byte(assumeRolePolicyDocument), &assumePolicyDoc)
			assert.NoError(t, err)

			assert.Contains(t, assumePolicyDoc.Statement[0].Principal.Aws, "root")
			assert.ElementsMatch(t, []string{
				"sts:AssumeRole",
				"sts:SetSourceIdentity",
				"sts:TagSession",
			}, assumePolicyDoc.Statement[0].Action)

			// Verify assume role conditions
			assert.NotNil(t, assumePolicyDoc.Statement[0].Condition)
			assert.Contains(t, assumePolicyDoc.Statement[0].Condition.ArnLike, "aws:PrincipalArn")
			assert.ElementsMatch(t, []string{
				fmt.Sprintf("arn:aws:iam::%s:role/tester-viewer", accountId),
				fmt.Sprintf("arn:aws:iam::%s:role/aws-reserved/sso.amazonaws.com*/AWSReservedSSO_IdentityViewerTeamAccess_*", accountId),
				"arn:aws:iam::*:user/*",
			},
				assumePolicyDoc.Statement[0].Condition.ArnLike["aws:PrincipalArn"])

			attachedPolicies, err = client.ListAttachedRolePolicies(context.Background(), &iam.ListAttachedRolePoliciesInput{
				RoleName: &viewerRoleName,
			})
			assert.NoError(t, err)

			expectedPolicies = []string{
				"arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
			}
			actualPolicies = []string{}
			for _, policy := range attachedPolicies.AttachedPolicies {
				actualPolicies = append(actualPolicies, *policy.PolicyArn)
			}

			assert.ElementsMatch(t, expectedPolicies, actualPolicies)

		})
	})
}
