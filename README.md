# Ring-Anti-Forgery [![Build Status](https://github.com/ring-clojure/ring-anti-forgery/actions/workflows/test.yml/badge.svg)](https://github.com/ring-clojure/ring-anti-forgery/actions/workflows/test.yml)

[Ring][] middleware that prevents [CSRF][] attacks. By default this uses
the [synchronizer token][] pattern.

[ring]: https://github.com/ring-clojure/ring
[csrf]: https://en.wikipedia.org/wiki/Cross-site_request_forgery
[synchronizer token]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Synchronizer_.28CSRF.29_Tokens

## Install

Add the following dependency to your `project.clj`:

    [ring/ring-anti-forgery "1.3.0"]

## Usage

The `wrap-anti-forgery` middleware function should be applied to your
Ring handler.

Once applied, any request that isn't a `HEAD` or `GET` request will
now require an anti-forgery token, or a 403 "access denied" response
will be returned.

By default, the request is validated via the synchronizer token
pattern, which requires the session middleware to be in place:

```clojure
(require '[ring.middleware.anti-forgery :refer :all]
         '[ring.middleware.session :refer :all])

(def app
  (-> handler
      wrap-anti-forgery
      wrap-session))
```

The token will be used to validate the request is accessible via the
`*anti-forgery-token*` var. The token is also placed in the request
under the `:anti-forgery-token` key.

### Custom token reader

By default the middleware looks for the anti-forgery token in the
`__anti-forgery-token` form parameter, which can be added to your
forms as a hidden field. For convenience, this library provides a
function to generate the HTML of that hidden field:

```clojure
(use 'ring.util.anti-forgery)

(anti-forgery-field)  ;; returns the HTML for the anti-forgery field
```

The middleware also looks for the token in the `X-CSRF-Token` and
`X-XSRF-Token` header fields, which are commonly used in AJAX
requests.

This behavior can be customized further by supplying a function to the
`:read-token` option. This function is passed the request map, and
should return the anti-forgery token found in the request.

```clojure
(defn get-custom-token [request]
  (get-in request [:headers "x-forgery-token"]))

(def app
  (-> handler
      (wrap-anti-forgery {:read-token get-custom-token})
      (wrap-session)))
```

### Custom error handling

It's also possible to customize the error response returned when the
token is invalid or missing:

```clojure
(def custom-error-response
  {:status 403
   :headers {"Content-Type" "text/html"}
   :body "<h1>Missing anti-forgery token</h1>"})

(def app
  (-> handler
      (wrap-anti-forgery {:error-response custom-error-response})
      (wrap-session)))
```

Or, for more control, an error handler can be supplied:

```clojure
(defn custom-error-handler [request]
  {:status 403
   :headers {"Content-Type" "text/html"}
   :body "<h1>Missing anti-forgery token</h1>"})

(def app
  (-> handler
      (wrap-anti-forgery {:error-handler custom-error-handler})
      (wrap-session)))
```

### Custom token strategy

The synchronizer pattern is not the only way of preventing CSRF
attacks. There a number of [different strategies][], and the
middleware in this library can support them through the `:strategy`
option:

```clojure
(def app
  (wrap-anti-forgery handler {:strategy custom-strategy}))
```

The custom strategy must satisfy the [Strategy protocol][]. Some
third-party strategies already exist:

* [Encrypted token strategy][]

[different strategies]: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#CSRF_Specific_Defense
[strategy protocol]: https://github.com/ring-clojure/ring-anti-forgery/blob/master/src/ring/middleware/anti_forgery/strategy.clj
[encrypted token strategy]: https://github.com/gorillalabs/ring-anti-forgery-strategies

## Further Documentation

* [API docs](https://ring-clojure.github.io/ring-anti-forgery/)

## Caveats

This middleware will prevent all HTTP methods except for GET and HEAD
from accessing your handler without a valid anti-forgery token.

You should therefore only apply this middleware to the parts of your
application designed to be accessed through a web browser. This
middleware should not be applied to handlers that define web services.

## License

Copyright © 2024 James Reeves

Distributed under the MIT License, the same as Ring.
