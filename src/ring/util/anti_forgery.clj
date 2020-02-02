(ns ring.util.anti-forgery
  "Utility functions for inserting anti-forgery tokens into HTML forms."
  (:require [hiccup.core :refer [html]]
            [hiccup.form :refer [hidden-field]]
            [ring.middleware.anti-forgery :refer [*anti-forgery-token*]]))

(defn anti-forgery-field-hiccup
  "The hiccup used to generate the result of anti-forgery-field."
  []
  (hidden-field "__anti-forgery-token" (force *anti-forgery-token*)))

(defn anti-forgery-field
  "Create a hidden field with the session anti-forgery token as its value.
  This ensures that the form it's inside won't be stopped by the anti-forgery
  middleware."
  []
  (html (anti-forgery-field-hiccup)))
