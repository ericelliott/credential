/**
 * credential
 *
 * Easy password hashing and verification in Node.
 * Protects against brute force, rainbow tables, and
 * timing attacks.
 *
 * Cryptographically secure per-password salts prevent
 * rainbow table attacks.
 *
 * Key stretching prevents brute force.
 *
 * Constant time verification prevents hang man timing
 * attacks.
 *
 * Created by Eric Elliott for the book,
 * "Programming JavaScript Applications" (O'Reilly)
 *
 * MIT license http://opensource.org/licenses/MIT
 */

'use strict';
var crypto = require('crypto'),
  mixIn = require('mout/object/mixIn'),
  constantTimeCompare = require('./constantTimeCompare'),

  msPerDay = 24 * 60 * 60 * 1000,
  msPerYear = 366 * msPerDay,
  y2k = new Date(2000, 0, 1),

  /**
   * pdkdf(password, salt, iterations,
   *   keyLength, callback) callback(err, hash)
   *
   * A standard to employ hashing and key stretching to
   * prevent rainbow table and brute-force attacks, even
   * if an attacker steals your password database.
   *
   * This function is a thin wrapper around Node's built-in
   * crypto.pbkdf2().
   *
   * See Internet Engineering Task Force RFC 2898
   * 
   * @param  {String}   password
   * @param  {String}   salt
   * @param  {Number}   iterations
   * @param  {Number}   keyLength
   * @param  {Function} callback
   * @return {undefined}
   */
  pbkdf2 = function pbkdf2(password, salt, iterations,
    keyLength, callback) {
    crypto.pbkdf2(password, salt,
      iterations, keyLength, function (err, hash) {
        if (err) {
          return callback(err);
        }
        callback(null, new Buffer(hash).toString('base64'));
      });
  },

  hashMethods = {
    pbkdf2: pbkdf2
  },

  /**
   * createSalt(keylength, callback) callback(err, salt)
   *
   * Generates a cryptographically secure random string for
   * use as a password salt using Node's built-in
   * crypto.randomBytes().
   *
   * @param  {Number} keyLength
   * @param  {Function} callback 
   * @return {undefined}
   */
  createSalt = function createSalt(keyLength, callback) {
    crypto.randomBytes(keyLength, function (err, buff) {
      if (err) {
        return callback(err);
      }
      callback(null, buff.toString('base64'));
    });
  },

  /**
   * iterations(work)
   *
   * Computes iterations based on current year and a shifting
   * factor.
   *
   * @param  {Number} work
   * @return {Number} iterations
   */

  iterations = function iterations( work, base ){
    var years = ((base || Date.now()) - y2k) / msPerYear;

    return Math.floor(1000 * Math.pow(2, years / 2) * work);
  },

  /**
   * expired(hash)
   *
   * Checks if a hash is older than the amount of days.
   *
   * @param  {Number} hash
   * @return {Number} days
   */

  expired = function expired( hash, days ){
    var base = Date.now() - (days || 90) * msPerDay;
    var minIterations = iterations(this.work, base);

    return JSON.parse(hash).iterations < minIterations;
  },

  /**
   * toHash(password, callback) callback(err, hash)
   *
   * Takes a new password and creates a unique hash. Passes
   * a JSON encoded object to the callback.
   *
   * @param  {[type]}   password
   * @param  {Function} callback
   */
  /**
   * callback
   * @param  {Error}  Error Error or null
   * @param  {String} hashObject JSON string
   * @param  {String} hashObject.hash
   * @param  {String} hashObject.salt
   * @param  {Number} hashObject.keyLength
   * @param  {String} hashObject.hashMethod
   * @param  {Number} hashObject.iterations
   * @return {undefined}
   */
  toHash = function toHash(password,
      callback) {
    var hashMethod = this.hashMethod,
      keyLength = this.keyLength,
      n = iterations(this.work);

    if (typeof (password) !== 'string' || password.length === 0) {
      return callback(new Error('Password must be a ' +
        ' non-empty string.'));
    }

    // Create the salt
    createSalt(keyLength, function (err, salt) {
      if (err) {
        return callback(err);
      }

      // Then create the hash
      hashMethods[hashMethod](password, salt,
          n, keyLength,
          function (err, hash) {

        if (err) {
          return callback(err);
        }

        callback(null, JSON.stringify({
          hash: hash,
          salt: salt,
          keyLength: keyLength,
          hashMethod: hashMethod,
          iterations: n
        }));

      });
    }.bind(this));
  },

  parseHash = function parseHash(encodedHash) {
    try {
      return JSON.parse(encodedHash);
    } catch (err) {
      return err;
    }
  },

  /**
   * verify(hash, input, callback) callback(err, isValid)
   *
   * Takes a stored hash, password input from the user,
   * and a callback, and determines whether or not the
   * user's input matches the stored password.
   *
   * @param  {String}   hash stored JSON object
   * @param  {String}   input user's password input
   * @param  {Function} callback(err, isValid)
   */
  verify = function verify(hash, input, callback) {
    var storedHash = parseHash(hash);

    if (!hashMethods[storedHash.hashMethod]) {
      return callback(new Error('Couldn\'t parse stored ' +
        'hash.'));
    }
    else if (typeof (input) !== 'string' || input.length === 0) {
        return callback(new Error('Input password must ' +
          ' be a non-empty string.'));
    }

    var n = storedHash.iterations;

    hashMethods[storedHash.hashMethod](input, storedHash.salt,
        n, storedHash.keyLength,
        function (err, newHash) {

      if (err) {
        return callback(err);
      }
      callback(null, constantTimeCompare(newHash, storedHash.hash));
    });
  },

  /**
   * configure(options)
   *
   * Alter settings.
   *
   * Warning: Decreasing `keyLength` or `work`
   * can make your password database less secure.
   *
   * @param  {Object} options Options object.
   * @param  {Number} options.keyLength
   * @param  {Number} options.work
   * @return {Object} credential object
   */
  configure = function configure(options) {
    mixIn(this, this.defaults, options);
    return this;
  },

  defaults = {
    keyLength: 66,
    work: 1,
    hashMethod: 'pbkdf2'
  };

module.exports = mixIn({}, defaults, {
  hash: toHash,
  verify: verify,
  expired: expired,
  configure: configure,
  iterations: iterations
});
