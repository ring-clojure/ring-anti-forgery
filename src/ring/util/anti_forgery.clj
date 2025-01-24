(ns ring.util.anti-forgery
  "Utility functions for inserting anti-forgery tokens into HTML forms."
  (:require [clojure.string :as str]
            [ring.middleware.anti-forgery :refer [*anti-forgery-token*]]))

(defn anti-forgery-field
  "Create a hidden field with the session anti-forgery token as its value.
  This ensures that the form it's inside won't be stopped by the anti-forgery
  middleware."
  []
  (str "<input id=\"__anti-forgery-token\" name=\"__anti-forgery-token\""
       " type=\"hidden\" value=\""
       (-> (force *anti-forgery-token*)
           (str/replace "&" "&amp;")
           (str/replace "\"" "&quot;")
           (str/replace "<" "&lt;"))
       "\" />"))
