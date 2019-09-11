package jwtmiddleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/smartystreets/goconvey/convey"
	"github.com/urfave/negroni"
)

func TestJwtMiddleware(t *testing.T) {
	os.Setenv("token_password", "this is a test")
	convey.Convey("Simple authenticated requests", t, func() {
		convey.Convey("Non authenticated GET to /protected path should return 403 response", func() {
			w := makeUnauthenticatedRequest("GET", "/protected")
			convey.So(w.Code, convey.ShouldEqual, http.StatusForbidden)
			convey.So(strings.TrimSpace(w.Body.String()), convey.ShouldEqual, "{\"message\":\"Missing auth token.\"}")
		})
		convey.Convey("Authenticated GET to /protected path should return 200 response", func() {
			token := fmt.Sprintf("Bearer %v", tokenString(jwt.SigningMethodHS256))
			w := makeAuthenticatedReqest("GET", "/protected", &token)
			convey.So(w.Code, convey.ShouldEqual, http.StatusOK)
			convey.So(strings.TrimSpace(w.Body.String()), convey.ShouldEqual, "{\"message\":\"got through protection\"}")
		})
		convey.Convey("Authenticated GET to /protected path with bad token signing method should return 403 response", func() {
			var token string = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg"
			w := makeAuthenticatedReqest("GET", "/protected", &token)
			convey.So(w.Code, convey.ShouldEqual, http.StatusForbidden)
			convey.So(strings.TrimSpace(w.Body.String()), convey.ShouldEqual, "{\"message\":\"Malformed authorization token. Unexpected signing method: RS256.\"}")
		})
		convey.Convey("Authenticated GET to /protected path with bad bearer token should return 403 response", func() {
			token := "Bearer thisisntajsonwebtoken"
			w := makeAuthenticatedReqest("GET", "/protected", &token)
			convey.So(w.Code, convey.ShouldEqual, http.StatusForbidden)
			convey.So(strings.TrimSpace(w.Body.String()), convey.ShouldEqual, "{\"message\":\"Malformed authorization token. token contains an invalid number of segments\"}")
		})
		convey.Convey("Authenticated GET to /protected path with non bearer token should return 403 response", func() {
			token := fmt.Sprintf("%v", tokenString(jwt.SigningMethodHS256))
			w := makeAuthenticatedReqest("GET", "/protected", &token)
			convey.So(w.Code, convey.ShouldEqual, http.StatusForbidden)
			convey.So(strings.TrimSpace(w.Body.String()), convey.ShouldEqual, "{\"message\":\"Invalid/Malformed auth token. Authorization Header must contain Bearer token.\"}")
		})
	})
}

func makeUnauthenticatedRequest(method string, url string) *httptest.ResponseRecorder {
	return makeAuthenticatedReqest(method, url, nil)
}

func makeAuthenticatedReqest(method string, url string, token *string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, url, nil)
	if token != nil {
		req.Header.Set("Authorization", *token)
	}
	w := httptest.NewRecorder()
	n := createMiddlewareRouter()
	n.ServeHTTP(w, req)
	return w
}

func tokenString(signingMethod jwt.SigningMethod) string {
	tk := jwt.New(signingMethod)
	token, _ := tk.SignedString([]byte(os.Getenv("token_password")))
	return token
}

func createMiddlewareRouter() *negroni.Negroni {
	// create protected mux router
	protectedRouter := mux.NewRouter().StrictSlash(true)
	protectedRouter.Use(JwtMiddleware)
	protectedRouter.Methods("GET").
		Path("/protected").
		Name("Protected").
		Handler(http.HandlerFunc(protectedHandler))

	negroniProtected := negroni.New()
	negroniProtected.UseHandler(protectedRouter)

	return negroniProtected
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	responseJson("got through protection", w)
}

type Response struct {
	Text string `json:"message"`
}

func responseJson(message string, w http.ResponseWriter) {
	response := Response{message}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(jsonResponse)
}
