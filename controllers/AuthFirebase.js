'use strict';

const _ = require('lodash');
const firebase = require('firebase-admin');
const jwt = require('jsonwebtoken');

/**
 * AuthFirebase.js controller
 *
 * @description: A set of functions called "actions" of the `auth-firebase` plugin.
 */

 function getToken(ctx) {
    var token = null

    // strapi.plugins['users-permissions'].services.jwt.getToken(ctx);
    // copied from above - without the verify part, and the exceptions
    if (ctx.request && ctx.request.header && ctx.request.header.authorization) {
      const parts = ctx.request.header.authorization.split(' ');

      if (parts.length === 2) {
        const scheme = parts[0];
        const credentials = parts[1];
        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        // throw new Error('Invalid authorization header format. Format is Authorization: Bearer [token]');
      }
    } else if (params.token) {
      token = params.token;
    } else {
      // throw new Error('No authorization header was found');
    }

    return token;
 }

module.exports = {

  /**
   * Default action.
   *
   * @return {Object}
   */

  index: async (ctx) => {
    // Add your own logic here.

    // Send 200 `ok`
    ctx.send({
      message: 'ok'
    });
  },

  verify: async (ctx) => {

    // ctx.send({
    //   message: 'verify'
    // });

    if (firebase.apps.length === 0) {
      firebase.initializeApp(strapi.config.firebase);
    }
    
    const params = _.assign({}, ctx.request.body, ctx.request.query);
    // console.log(params);
    var token = getToken(ctx);
    async function verifyIdToken (token) {
      if (!token) {
        return null;
      }
      return await firebase.auth().verifyIdToken(token)
      .then(function(decodedToken) {
        return decodedToken;
      }).catch(function(error) {
        console.log(error);
        return null;
      });
    }

    const decoded = await verifyIdToken(token) || { email: null };
    console.log(decoded);
    let user = decoded.email ?
      await strapi.plugins['users-permissions'].models.user
        .findOne({ email: decoded.email }, ['role', 'meta'])
      : null;

    // console.log(decoded);

    // if null ..add to database 
    var values = {};
    if (!user && decoded.email && decoded.email.includes('@')) {

      values = {
        username: decoded.email.split('@')[0],
        email: decoded.email,
        provider: 'firebase',
        blocked: false,
        confirmed: true,
        meta: {}
      }

      // console.log(decoded.firebase);
      // console.log(decoded.firebase.identities);
      // return ctx.send({});

      if (values.password) {
        values.password = await strapi.plugins['users-permissions'].services.user.hashPassword(values);
      }

      const role = await strapi.plugins['users-permissions'].models.role
        .findOne({ type: 'authenticated' });

      values.role = role._id || role.id;

     // Use Content Manager business logic to handle relation.
      if (strapi.plugins['content-manager']) {
        await strapi.plugins['content-manager'].services['contentmanager'].create(values, {
          model: 'user',
          source: 'users-permissions'
        });
      }

      user = await strapi.plugins['users-permissions'].models.user
        .findOne({ email: decoded.email }, ['role', 'meta']);
    }

    if (!user) {
      return ctx.badRequest(null, ctx.request.admin ? [{ messages: [{ id: 'Auth.form.error.invalid' }] }] : 'Token invalid.');
    }

    // update identities
    let meta = {
      identities: {}
    }

    if (decoded.firebase) {
      Object.keys(decoded.firebase.identities).forEach(k => {
        let kCleaned = k.replace('.', '-');
        meta.identities[kCleaned] = decoded.firebase.identities[k];
      })
    }

   if(user.meta.name == null && user.meta.email == null) {

    console.log('Saving user..');
      /// update
      user.meta = {
        ... user.meta,
        ... meta,
        name: decoded.name,
        photoUrl: decoded.picture,
        email: decoded.email
      }

      // console.log(decoded);
      
      const newUser = await strapi.plugins['users-permissions'].models.user.updateOne({
          _id: user.id
        }, user);

        console.log(newUser);

      console.log('--------------------');
      console.log(user);
      console.log('<<<');
   }

    ctx.send({
        jwt: strapi.plugins['users-permissions'].services.jwt.issue(_.pick(user, ['_id', 'id'])),
        user: _.omit(user.toJSON ? user.toJSON() : user, ['password', 'resetPasswordToken'])
      });
  },

  // -------------------------
  // move somewhere else?

  me: async (ctx) => {
    var res = await strapi.plugins['users-permissions'].services.jwt.getToken(ctx);
    if (!res || !res.id) {
      return ctx.badRequest(null, ctx.request.admin ? [{ messages: [{ id: 'Auth.form.error.invalid' }] }] : 'Token invalid.');
    }

    let user = await strapi.plugins['users-permissions'].models.user
        .findOne({ id: res.id }, ['meta']);

    ctx.send(user);
  },

  update: async (ctx) => {
    var res = await strapi.plugins['users-permissions'].services.jwt.getToken(ctx);
    if (!res || !res.id) {
      return ctx.badRequest(null, ctx.request.admin ? [{ messages: [{ id: 'Auth.form.error.invalid' }] }] : 'Token invalid.');
    }

    let user = await strapi.plugins['users-permissions'].models.user
        .findOne({ _id: res.id }, ['meta']);

    let updateUser = { ...ctx.request.body };
    console.log(user);
    delete updateUser._id;
    if(user.meta === null) {
      user.meta = {};
    }
    Object.assign(user.meta, updateUser);

    res = await strapi.plugins['users-permissions'].models.user.updateOne({_id: res.id }, user);

    ctx.send(user);
  }
};
