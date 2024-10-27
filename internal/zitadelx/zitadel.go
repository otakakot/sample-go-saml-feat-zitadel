package zitadelx

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

func CreateProject(
	ctx context.Context,
	name string,
	meta []byte,
) error {
	initial := client.DefaultServiceUserAuthentication("./machinekey/zitadel-admin-sa.json", oidc.ScopeOpenID, client.ScopeZitadelAPI())

	cli, err := client.New(
		ctx,
		zitadel.New("localhost", zitadel.WithInsecure("8080")),
		client.WithAuth(initial),
	)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	proj, err := cli.ManagementService().AddProject(ctx, &management.AddProjectRequest{
		Name:                   name,
		ProjectRoleAssertion:   false,
		ProjectRoleCheck:       false,
		HasProjectCheck:        false,
		PrivateLabelingSetting: 0,
	})
	if err != nil {
		return fmt.Errorf("add project: %w", err)
	}

	slog.Info(fmt.Sprintf("project: %+v", proj))

	app, err := cli.ManagementService().AddSAMLApp(ctx, &management.AddSAMLAppRequest{
		ProjectId: proj.GetId(),
		Name:      name,
		Metadata: &management.AddSAMLAppRequest_MetadataXml{
			MetadataXml: meta,
		},
	})
	if err != nil {
		return fmt.Errorf("add saml app: %w", err)
	}

	slog.Info(fmt.Sprintf("app: %+v", app))

	return nil
}

func CreateUser(
	ctx context.Context,
	email string,
) error {
	slog.Info("start user creation ... ")

	initial := client.DefaultServiceUserAuthentication("./machinekey/zitadel-admin-sa.json", oidc.ScopeOpenID, client.ScopeZitadelAPI())

	cli, err := client.New(
		ctx,
		zitadel.New("localhost", zitadel.WithInsecure("8080")),
		client.WithAuth(initial),
	)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	us, err := cli.UserServiceV2().AddHumanUser(ctx, &user.AddHumanUserRequest{
		Profile: &user.SetHumanProfile{
			GivenName:  "test",
			FamilyName: "test",
		},
		Email: &user.SetHumanEmail{
			Email: email,
			Verification: &user.SetHumanEmail_IsVerified{
				IsVerified: true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("add human user: %w", err)
	}

	slog.Info(fmt.Sprintf("email: %s", email))

	if _, err := cli.UserServiceV2().SetPassword(ctx, &user.SetPasswordRequest{
		UserId: us.UserId,
		NewPassword: &user.Password{
			Password: "P@ssword1",
		},
	}); err != nil {
		return fmt.Errorf("set password: %w", err)
	}

	return nil
}
