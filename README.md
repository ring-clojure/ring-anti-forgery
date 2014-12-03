# Ring-Anti-Forgery

[![Build Status](https://secure.travis-ci.org/ring-clojure/ring-anti-forgery.png)](http://travis-ci.org/ring-clojure/ring-anti-forgery)

Ring middleware that prevents [CSRF][1] attacks by via a
randomly-generated anti-forgery token.

[1]: http://en.wikipedia.org/wiki/Cross-site_request_forgery

## Install

Add the following dependency to your `project.clj`:

    [ring/ring-anti-forgery "1.0.0"]

## Usage

The `wrap-anti-forgery` middleware should be applied to your Ring
handler, inside of the standard `wrap-session` middleware in Ring:

```clojure
(use 'ring.middleware.anti-forgery
     'ring.middleware.session)

(def app
  (-> handler
      wrap-anti-forgery
      wrap-session))
```

Any request that isn't a `HEAD` or `GET` request will now require an
anti-forgery token, or an "access denied" response will be returned.
The token is bound to the session, and accessible via the
`*anti-forgery-token*` var.

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

## Caveats

This middleware will prevent all HTTP methods except for GET and HEAD
from accessing your handler without an anti-forgery token that matches
the one in the current session.

You should therefore only apply this middleware to the parts of your
application designed to be accessed through a web browser. This
middleware should not be applied to handlers that define web services.
For instance, in [Compojure][2] you could write:

[2]: https://github.com/weavejester/compojure

```clojure
(routes
 api-routes
 (wrap-anti-forgery site-routes))
```

## License

Copyright © 2014 James Reeves

Distributed under the MIT License, the same as Ring.
