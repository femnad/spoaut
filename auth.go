package spoaut

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/zmb3/spotify/v2"
	"github.com/zmb3/spotify/v2/auth"
	"golang.org/x/oauth2"

	"github.com/femnad/mare"
	"github.com/femnad/spoaut/appconfig"
)

type Config struct {
	ConfigFile string
	Scopes     []string
	TokenFile  string
	appCfg     appconfig.Config
}

type authResult struct {
	err   error
	token *oauth2.Token
}

var (
	authResultCh = make(chan authResult)
)

func generateState() string {
	return uuid.New().String()
}

func closeAndCheck(closer io.Closer) {
	err := closer.Close()
	if err != nil {
		log.Fatalf("error closing file %v", err)
	}
}

type auther struct {
	auth      *spotifyauth.Authenticator
	config    Config
	tokenFile string
}

func getAuthenticator(config Config) (*spotifyauth.Authenticator, error) {
	var a *spotifyauth.Authenticator
	appCfg := config.appCfg

	authOptions := []spotifyauth.AuthenticatorOption{
		spotifyauth.WithRedirectURL(appCfg.RedirectURI()),
		spotifyauth.WithScopes(config.Scopes...),
	}

	if !appCfg.ClientIdInEnv() {
		clientId, err := appCfg.ClientId()
		if err != nil {
			return a, err
		}
		authOptions = append(authOptions, spotifyauth.WithClientID(clientId))
	}
	if !appCfg.ClientSecretInEnv() {
		clientSecret, err := appCfg.ClientSecret()
		if err != nil {
			return a, err
		}
		authOptions = append(authOptions, spotifyauth.WithClientSecret(clientSecret))
	}

	return spotifyauth.New(authOptions...), nil
}

func newAuther(config Config) (auther, error) {
	var a auther

	appCfg, err := appconfig.Get(config.ConfigFile)
	if err != nil {
		return a, err
	}
	config.appCfg = appCfg

	auth, err := getAuthenticator(config)
	if err != nil {
		return a, err
	}

	tokenFile := mare.ExpandUser(config.TokenFile)
	return auther{
		auth:      auth,
		config:    config,
		tokenFile: tokenFile,
	}, nil
}

func (a auther) saveToken(token oauth2.Token) error {
	dir, _ := path.Split(a.tokenFile)
	err := mare.EnsureDir(dir)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(a.tokenFile, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer closeAndCheck(f)

	encoder := json.NewEncoder(f)
	return encoder.Encode(token)
}

func (a auther) hasSavedToken() (bool, error) {
	_, err := os.Stat(a.tokenFile)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, err
	}
}

func (a auther) saveTokenFromClient(client *spotify.Client) error {
	token, err := client.Token()
	if err != nil {
		return fmt.Errorf("error getting token from client: %v", err)
	}

	return a.saveToken(*token)
}

func (a auther) clientFromSavedToken(ctx context.Context) (*spotify.Client, error) {
	f, err := os.Open(a.tokenFile)
	if err != nil {
		return &spotify.Client{}, err
	}
	defer closeAndCheck(f)

	var token oauth2.Token
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&token)
	if err != nil {
		return &spotify.Client{}, err
	}

	client := spotify.New(a.auth.Client(ctx, &token))
	if token.Expiry.Before(time.Now()) {
		err = a.saveTokenFromClient(client)
		if err != nil {
			return &spotify.Client{}, err
		}
	}

	return client, nil
}

// Mostly derived from https://github.com/zmb3/spotify/blob/master/examples/authenticate/authcode/authenticate.go.
func (a auther) authenticate(ctx context.Context) (*spotify.Client, error) {
	var client *spotify.Client
	appCfg := a.config.appCfg

	callbackPath, err := appCfg.Path()
	if err != nil {
		return &spotify.Client{}, fmt.Errorf("error determining path of callback URI: %v", err)
	}

	state := generateState()
	completeAuth := func(w http.ResponseWriter, r *http.Request) {
		tok, rErr := a.auth.Token(r.Context(), state, r)
		if rErr != nil {
			http.Error(w, "Couldn't get token", http.StatusForbidden)
			authResultCh <- authResult{err: rErr}
			return
		}

		if st := r.FormValue("state"); st != state {
			http.NotFound(w, r)
			rErr = fmt.Errorf("State mismatch: %s != %s\n", st, state)
			authResultCh <- authResult{err: rErr}
			return
		}

		authResultCh <- authResult{token: tok, err: nil}
	}

	port, err := appCfg.Port()
	if err != nil {
		return &spotify.Client{}, fmt.Errorf("error determining port of callback URI")
	}

	http.HandleFunc(callbackPath, completeAuth)
	go func() {
		addr := fmt.Sprintf(":%s", port)
		hErr := http.ListenAndServe(addr, nil)
		if hErr != nil {
			log.Fatalf("error listening for redirect response: %v", hErr)
		}
	}()

	authUrl := a.auth.AuthURL(state)
	fmt.Println("Visit the following page:", authUrl)

	result := <-authResultCh
	resultErr := result.err
	if resultErr != nil {
		return &spotify.Client{}, resultErr
	}

	client = spotify.New(a.auth.Client(ctx, result.token))

	user, err := client.CurrentUser(ctx)
	if err != nil {
		return &spotify.Client{}, err
	}

	log.Printf("Logged as %s", user.ID)

	err = a.saveToken(*result.token)
	if err != nil {
		return &spotify.Client{}, err
	}

	return client, nil
}

func (a auther) getClient(ctx context.Context) (*spotify.Client, error) {
	var c *spotify.Client

	hasToken, err := a.hasSavedToken()
	if err != nil {
		return c, fmt.Errorf("error checking for saved auth token: %v", err)
	}

	if hasToken {
		c, err = a.clientFromSavedToken(ctx)
		if err != nil {
			return &spotify.Client{}, fmt.Errorf("error authenticating with saved token: %v", err)
		}
		return c, nil
	}

	c, err = a.authenticate(ctx)
	if err != nil {
		return c, fmt.Errorf("error authenticating for the first time: %v", err)
	}
	return c, nil
}

func Client(ctx context.Context, config Config) (*spotify.Client, error) {
	var c *spotify.Client

	a, err := newAuther(config)
	if err != nil {
		return c, err
	}

	return a.getClient(ctx)
}
