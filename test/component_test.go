package test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/cloudposse/test-helpers/pkg/atmos"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
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

type TeamConfig struct {
	AllowedRoles          map[string]interface{} `json:"allowed_roles"`
	AwsSamlLoginEnabled   bool                    `json:"aws_saml_login_enabled"`
	DeniedPermissionSets   []string                `json:"denied_permission_sets"`
	DeniedRoleArns        []string                `json:"denied_role_arns"`
	DeniedTeams           []string                `json:"denied_teams"`
	MaxSessionDuration    int                     `json:"max_session_duration"`
	RoleDescription       string                  `json:"role_description"`
	RolePolicyArns       []string                `json:"role_policy_arns"`
	TrustedPermissionSets  []string                `json:"trusted_permission_sets"`
	TrustedRoleArns       []string                `json:"trusted_role_arns"`
	TrustedTeams          []string                `json:"trusted_teams"`
}

type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestBasic() {
	const component = "aws-teams/basic"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	assert.NotNil(s.T(), options)

	rolesMap := atmos.OutputMapOfObjects(s.T(), options, "team_name_role_arn_map")
	assert.NotEmpty(s.T(), rolesMap["admin"])
	assert.NotEmpty(s.T(), rolesMap["viewer"])

	expectedNames := []string{
		strings.Split(rolesMap["admin"].(string), "/")[1],
		strings.Split(rolesMap["viewer"].(string), "/")[1],
	}
	names := atmos.OutputList(s.T(), options, "team_names")
	assert.ElementsMatch(s.T(), expectedNames, names)

	expectedArns := []string{
		rolesMap["admin"].(string),
		rolesMap["viewer"].(string),
	}
	arns := atmos.OutputList(s.T(), options, "role_arns")
	assert.ElementsMatch(s.T(), expectedArns, arns)


	var config map[string]TeamConfig
	atmos.OutputStruct(s.T(), options, "teams_config", &config)
	adminRoleDescription := config["admin"].RoleDescription
	viewerRoleDescription := config["viewer"].RoleDescription

	assert.True(s.T(), config["admin"].AwsSamlLoginEnabled)
	assert.Equal(s.T(), "viewer", config["admin"].DeniedTeams[0])
	assert.EqualValues(s.T(), 43200, config["admin"].MaxSessionDuration)
	assert.Equal(s.T(), "Team with PowerUserAccess permissions in `identity` and AdministratorAccess to all other accounts except `root`", adminRoleDescription)
	assert.Equal(s.T(), "arn:aws:iam::aws:policy/PowerUserAccess", config["admin"].RolePolicyArns[0])
	assert.Equal(s.T(), "IdentityAdminTeamAccess", config["admin"].TrustedPermissionSets[0])
	assert.Equal(s.T(), "admin", config["admin"].TrustedTeams[0])

	assert.False(s.T(), config["viewer"].AwsSamlLoginEnabled)
	assert.Equal(s.T(), "viewer", config["viewer"].DeniedTeams[0])
	assert.EqualValues(s.T(), 43200, config["viewer"].MaxSessionDuration)
	assert.Equal(s.T(), "Team restricted to viewing resources in the identity account", viewerRoleDescription)
	assert.Equal(s.T(), "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", config["viewer"].RolePolicyArns[0])

	client := aws.NewIamClient(s.T(), awsRegion)

	adminRoleName := strings.Split(rolesMap["admin"].(string), "/")[1]
	viewerRoleName := strings.Split(rolesMap["viewer"].(string), "/")[1]

	verifyRole(s.T(), client, adminRoleName, "admin")
	verifyRole(s.T(), client, viewerRoleName, "viewer")

	s.DriftTest(component, stack, nil)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "aws-teams/disabled"
	const stack = "default-test"
	const awsRegion = "us-east-2"

	s.VerifyEnabledFlag(component, stack, nil)
}

func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}

func verifyRole(t *testing.T, client *iam.Client, roleName, roleType string) {
	describeRoleOutput, err := client.GetRole(context.Background(), &iam.GetRoleInput{
		RoleName: &roleName,
	})
	assert.NoError(t, err)

	awsRole := describeRoleOutput.Role
	assert.Equal(t, roleName, *awsRole.RoleName)

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

	// Additional assertions for role details can be added here
}
