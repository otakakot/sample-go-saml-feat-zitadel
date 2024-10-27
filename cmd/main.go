package main

import (
	"context"
	"io"
	"net/http"

	"github.com/otakakot/sample-go-saml-feat-zitadel/internal/zitadelx"
)

func main() {
	// if err := zitadelx.CreateUser(context.Background(), "test@example.com"); err != nil {
	// 	panic(err)
	// }

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"http://localhost:7070/saml/metadata",
		nil,
	)
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/xml")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	meta, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	if err := zitadelx.CreateProject(context.Background(), "saml3", meta); err != nil {
		panic(err)
	}
}
