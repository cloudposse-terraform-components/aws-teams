package test

import (
	"strings"
	"testing"

	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/aws-component-helper"
	"github.com/stretchr/testify/assert"
)

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
			assert.True(t, config["admin"].(map[string]interface{})["aws_saml_login_enabled"].(bool))
			assert.Equal(t, "viewer", config["admin"].(map[string]interface{})["denied_teams"].([]interface{})[0].(string))
			assert.Equal(t, float64(43200), config["admin"].(map[string]interface{})["max_session_duration"].(float64))
			assert.Equal(t, "Team with PowerUserAccess permissions in `identity` and AdministratorAccess to all other accounts except `root`", config["admin"].(map[string]interface{})["role_description"].(string))
			assert.Equal(t, "arn:aws:iam::aws:policy/PowerUserAccess", config["admin"].(map[string]interface{})["role_policy_arns"].([]interface{})[0].(string))
			assert.Equal(t, "IdentityAdminTeamAccess", config["admin"].(map[string]interface{})["trusted_permission_sets"].([]interface{})[0].(string))
			assert.Equal(t, "admin", config["admin"].(map[string]interface{})["trusted_teams"].([]interface{})[0].(string))

			assert.False(t, config["viewer"].(map[string]interface{})["aws_saml_login_enabled"].(bool))
			assert.Equal(t, "viewer", config["viewer"].(map[string]interface{})["denied_teams"].([]interface{})[0].(string))
			assert.Equal(t, float64(43200), config["viewer"].(map[string]interface{})["max_session_duration"].(float64))
			assert.Equal(t, "Team restricted to viewing resources in the identity account", config["viewer"].(map[string]interface{})["role_description"].(string))
			assert.Equal(t, "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", config["viewer"].(map[string]interface{})["role_policy_arns"].([]interface{})[0].(string))
		})
	})
}
