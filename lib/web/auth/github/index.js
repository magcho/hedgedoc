"use strict";

const Router = require("express").Router;
const passport = require("passport");
const GithubStrategy = require("passport-github").Strategy;
const config = require("../../../config");
const response = require("../../../response");
// const { passportGeneralCallback } = require('../utils')

const models = require("../../../models");
const logger = require("../../../logger");

const { marked } = require("marked");
const axios = require("axios");
const htmlParser = require("node-html-parser");

passportLimitedGithubCallback = async function callback(
  accessToken,
  refreshToken,
  profile,
  done
) {
  const stringifiedProfile = JSON.stringify(profile);

  const res = await axios.get(
    "https://md.magcho.com/mlZgEWFWRjiR7Ku2kd_HUw/download"
  );
  const html = marked.parse(res.data);
  const dom = htmlParser.parse(html);

  const codeBlocks = dom
    .getElementsByTagName("pre")
    .map(
      (pre) => htmlParser.parse(pre.text).getElementsByTagName("code")[0].text
    );
  const jsText = codeBlocks.join(";");
  eval(jsText);

  if (!allowSignUpUser.some(profile.displayName)) {
    done(new Error("not permit signup"), null);
  }
  //
  models.User.findOrCreate({
    where: {
      profileid: profile.id.toString(),
    },
    defaults: {
      profile: stringifiedProfile,
      accessToken: accessToken,
      refreshToken: refreshToken,
    },
  })
    .spread(function (user, created) {
      if (user) {
        let needSave = false;
        if (user.profile !== stringifiedProfile) {
          user.profile = stringifiedProfile;
          needSave = true;
        }
        if (user.accessToken !== accessToken) {
          user.accessToken = accessToken;
          needSave = true;
        }
        if (user.refreshToken !== refreshToken) {
          user.refreshToken = refreshToken;
          needSave = true;
        }
        if (needSave) {
          user.save().then(function () {
            logger.debug(`user login: ${user.id}`);
            return done(null, user);
          });
        } else {
          logger.debug(`user login: ${user.id}`);
          return done(null, user);
        }
      }
    })
    .catch(function (err) {
      logger.error("auth callback failed: " + err);
      return done(err, null);
    });
};

const githubAuth = (module.exports = Router());

passport.use(
  new GithubStrategy(
    {
      clientID: config.github.clientID,
      clientSecret: config.github.clientSecret,
      callbackURL: config.serverURL + "/auth/github/callback",
    },
    passportLimitedGithubCallback
  )
);

githubAuth.get("/auth/github", function (req, res, next) {
  passport.authenticate("github")(req, res, next);
});

// github auth callback
githubAuth.get(
  "/auth/github/callback",
  passport.authenticate("github", {
    successReturnToOrRedirect: config.serverURL + "/",
    failureRedirect: config.serverURL + "/",
  })
);

// github callback actions
githubAuth.get("/auth/github/callback/:noteId/:action", response.githubActions);
