package decoder

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	zLog "github.com/rs/zerolog/log"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	statusKey = "status"
)

// Server is a http handler that will use a decoder to decode the authHeaderKey JWT-Token
// and put the resulting claims in headers
type Server struct {
	decoder                 TokenDecoder
	authHeaderKey           string
	tokenValidatedHeaderKey string
	multiClusterPrefix      string
	secretCacheTTL          int64
	jwksURL                 string
	clientset               *kubernetes.Clientset
	cachedTokenMap          map[string]CachedToken
	validateAPIPaths        string
	usernameClaim           string
}

type CachedToken struct {
	token      string
	validUntil int64
}

// NewServer returns a new server that will decode the header with key authHeaderKey
// with the given TokenDecoder decoder.
func NewServer(decoder TokenDecoder, authHeaderKey, tokenValidatedHeaderKey string, multiClusterPrefix string, jwksURL string, clientset *kubernetes.Clientset, secretCacheTTL int64, validateAPIPaths string, usernameClaim string) *Server {
	cachedTokenMap := map[string]CachedToken{}
	return &Server{decoder: decoder, authHeaderKey: authHeaderKey, tokenValidatedHeaderKey: tokenValidatedHeaderKey, multiClusterPrefix: multiClusterPrefix, jwksURL: jwksURL, clientset: clientset, cachedTokenMap: cachedTokenMap, secretCacheTTL: secretCacheTTL, validateAPIPaths: validateAPIPaths, usernameClaim: usernameClaim}
}

// DecodeToken http handler
func (s *Server) DecodeToken(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zLog.Ctx(ctx)
	uri := r.Header.Clone().Get("X-Forwarded-Uri")
	timeNow := time.Now().Unix()
	var authToken string

	if _, ok := r.Header[s.authHeaderKey]; !ok {
		originQuery, _ := url.ParseQuery(uri)
		queryToken := originQuery.Get("token")
		// log.Debug().Int(statusKey, http.StatusOK).Str(s.tokenValidatedHeaderKey, "false").Msgf("Check query token %s", queryToken)

		if queryToken == "" {
			log.Debug().Int(statusKey, http.StatusUnauthorized).Str(s.tokenValidatedHeaderKey, "false").Msgf("no auth header %s, early exit", s.authHeaderKey)
			rw.Header().Set(s.tokenValidatedHeaderKey, "false")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			log.Debug().Msgf("query token %s, continue", s.authHeaderKey)
			authToken = queryToken
		}
	} else {
		authHeader := r.Header.Clone().Get(s.authHeaderKey)
		authToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	tokenByteArr, err := jwt.DecodeSegment(strings.Split(authToken, ".")[1])

	if err != nil {
		log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to decode jwt token segment.")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	var decodedTokenMap map[string]interface{}
	json.Unmarshal(tokenByteArr, &decodedTokenMap)
	issuer := decodedTokenMap["iss"].(string)

	isSAToken := issuer == "kubernetes/serviceaccount"

	parsedJwksURL, _ := url.Parse(s.jwksURL)
	isOIDCToken := strings.Contains(s.jwksURL, issuer) && strings.Contains(issuer, parsedJwksURL.Scheme+"://"+parsedJwksURL.Host)

	isMultiCluster := strings.Split(r.Header.Clone().Get("X-Forwarded-Host"), ".")[0] == s.multiClusterPrefix

	var needSATokenValidation bool

	for _, path := range strings.Split(s.validateAPIPaths, ",") {
		if strings.Contains(uri, path) {
			needSATokenValidation = true
			break
		}
	}

	if !isSAToken && !isOIDCToken {
		log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("token with unknown issuer.")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	if isSAToken {
		log.Debug().Msgf("received request uri %s with service account token.", uri)

		if needSATokenValidation {
			namespace := decodedTokenMap["kubernetes.io/serviceaccount/namespace"].(string)
			secretname := decodedTokenMap["kubernetes.io/serviceaccount/secret.name"].(string)

			cachedToken, exists := s.cachedTokenMap[namespace+":"+secretname]

			if (!exists) || (timeNow > cachedToken.validUntil) {
				log.Debug().Msgf("cached token is either too old or does not exist.")
				secret, err := s.clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretname, metav1.GetOptions{})

				if errors.IsNotFound(err) {
					log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("secret %s not found in %s namespace.", secretname, namespace)
					rw.WriteHeader(http.StatusUnauthorized)
					return
				}

				if err != nil {
					log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("error getting secret %s in %s namespace. %s", secretname, namespace, err.Error())
					rw.WriteHeader(http.StatusUnauthorized)
					return
				}

				s.cachedTokenMap[namespace+":"+secretname] = CachedToken{
					token:      string(secret.Data["token"][:]),
					validUntil: timeNow + s.secretCacheTTL,
				}

				log.Debug().Msgf("token %s added or refreshed to cache.", namespace+":"+secretname)
			}

			log.Debug().Msgf("using cached token %s. valid for %ss.", namespace+":"+secretname, strconv.FormatInt(s.cachedTokenMap[namespace+":"+secretname].validUntil-timeNow, 10))

			if authToken != s.cachedTokenMap[namespace+":"+secretname].token {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("invalid service account token %s.", namespace+":"+secretname)
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}

			// log.Debug().Int(statusKey, http.StatusOK).Msgf("service account token verified, secretname=%s, namespace=%s", secretname, namespace)
			log.Debug().Msgf("service account token %s verified.", namespace+":"+secretname)
		}
	}

	if isOIDCToken {

		if isMultiCluster || needSATokenValidation {
			t, err := s.decoder.Decode(ctx, authToken)

			if err != nil {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to decode token")
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}

			if err = t.Validate(); err != nil {
				log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msg("unable to validate token")
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}

			for k, v := range t.Claims {
				rw.Header().Set(k, v)
				log.Debug().Str(k, v)
			}
		}

		if isMultiCluster {
			log.Debug().Msgf("request to remote cluster %s.", strings.Split(uri, "/")[3])

			re, _ := regexp.Compile("[" + regexp.QuoteMeta(`!#$%&'"*+-/=?^_{|}~().,:;<>[]\`) + "`\\s" + "]")
			username := decodedTokenMap[s.usernameClaim].(string)
			usernameEscaped := re.ReplaceAllString(strings.Replace(username, "@", "-at-", -1), "-")
			namespace := strings.Split(uri, "/")[2]
			clustername := strings.Split(uri, "/")[3]
			secretname := usernameEscaped + "-" + clustername + "-token"

			cachedToken, exists := s.cachedTokenMap[namespace+":"+secretname]

			if (!exists) || (timeNow > cachedToken.validUntil) {
				log.Debug().Msgf("cached token is either too old or does not exist.")

				secret, err := s.clientset.CoreV1().Secrets(namespace).Get(context.TODO(), secretname, metav1.GetOptions{})

				if errors.IsNotFound(err) {
					log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("secret %s not found in %s namespace.", secretname, namespace)
					rw.WriteHeader(http.StatusUnauthorized)
					return
				}

				if err != nil {
					log.Warn().Err(err).Int(statusKey, http.StatusUnauthorized).Msgf("error getting secret %s in %s namespace: %s", secretname, namespace, err.Error())
					rw.WriteHeader(http.StatusUnauthorized)
					return
				}

				s.cachedTokenMap[namespace+":"+secretname] = CachedToken{
					token:      string(secret.Data["token"][:]),
					validUntil: timeNow + s.secretCacheTTL,
				}

				log.Debug().Msgf("token %s added or refreshed to cache.", namespace+":"+secretname)
			}

			log.Debug().Msgf("using cached token %s. valid for %ss.", namespace+":"+secretname, strconv.FormatInt(s.cachedTokenMap[namespace+":"+secretname].validUntil-timeNow, 10))
			// log.Debug().Int(statusKey, http.StatusOK).Msgf("using token from secret %s in namespace %s.", secretname, namespace)

			authToken = s.cachedTokenMap[namespace+":"+secretname].token
		}
	}

	rw.Header().Set(s.authHeaderKey, "Bearer "+authToken)
	rw.Header().Set(s.tokenValidatedHeaderKey, "true")
	log.Debug().Int(statusKey, http.StatusOK).Msg("ok")
	rw.WriteHeader(http.StatusOK)
	return
}
