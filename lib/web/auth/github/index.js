"use strict";

const Router = require("express").Router;
const passport = require("passport");
const GithubStrategy = require("passport-github").Strategy;
const config = require("../../../config");
const response = require("../../../response");
// const { passportGeneralCallback } = require('../utils')

const models = require("../../../models");
const logger = require("../../../logger");

const axios = require("axios");

async function passportLimitedGithubCallback(
  accessToken,
  refreshToken,
  profile,
  done
) {
  const stringifiedProfile = JSON.stringify(profile);

  const res = await axios.get(
    "https://gist.githubusercontent.com/magcho/bebda0c4dd507d30eefae588b2b00d3c/raw/2ab6a0fdb46dd3da9b84981e57242a588f688cb2/hedgedoc-permit.json"
  );
  const limitConfig = res.data;

  if (!limitConfig.permitUser.some((user) => user === profile.username)) {
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
}

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
