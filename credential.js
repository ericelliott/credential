/**
 * credential
 *
 * Fortify your user's passwords against rainbow table and
 * brute force attacks using Node's built in crypto functions.
 *
 * Employs cryptographically secure, password unique salts to
 * prevent rainbow table attacks.
 *
 * Key stretching is used to make brute force attacks
 * impractical.
 *
 * Created by Eric Elliott for the book,
 * "Programming JavaScript Applications" (O'Reilly)
 *
 * MIT license http://opensource.org/licenses/MIT
 */

var crypto = require('crypto'),
  mixIn = require('mout/object/mixIn'),
  pick = require('mout/object/pick'),

  /**
   * pbkdf2(password, salt, callback)
   *
   * A standard to employ hashing and key stretching to
   * prevent rainbow table and brute-force attacks, even
   * if an attacker steals your password database.
   *
   * This function is a thin wrapper around Node's built-in
   * crypto.pbkdf2().
   *
   * Internet Engineering Task Force's RFC 2898
   * @param  {[type]}   password
   * @param  {[type]}   salt
   * @param  {Function} callback err, buffer
   */
  pbkdf2 = function pbkdf2(password, salt, callback) {
    crypto.pbkdf2(password, salt,
      this.iterations, this.keylength, function (err, buff) {
        if (err) {
          return callback(err);
        }
        callback(null, buff.toString('base64'));
      });
  },

  /**
   * createSalt(callback)
   *
   * Generates a cryptographically secure random string for
   * use as a password salt using Node's built-in
   * crypto.randomBytes().
   *
   * @param  {Function} callback [description]
   * @return {[type]}            [description]
   */
  createSalt = function createSalt(callback) {
    crypto.randomBytes(this.keylength, function (err, buff) {
      if (err) {
        return callback(err);
      }
      callback(null, buff.toString('base64'));
    });
  },

  /**
   * toHash(password, callback)
   *
   * Takes a new password and creates a unique salt and hash
   * combination in the form `salt$hash`, suitable for storing
   * in a single text field.
   *
   * @param  {[type]}   password
   * @param  {Function} callback
   */
  toHash = function toHash(password,
      callback) {

    // Create the salt
    createSalt.call(this, function (err, salt) {
      if (err) {
        return callback(err);
      }

      salt = salt.toString('base64');

      // Then create the hash
      pbkdf2.call(this, password, salt, function (err, hash) {
        if (err) {
          return callback(err);
        }

        callback(null, salt + '$' + hash.toString('base64'));
      });
    }.bind(this));
  },

  /**
   * constantEquals(x, y)
   *
   * Compare two equal-length hashes, x and y with a
   * constant-time algorithm to prevent attacks based on
   * timing statistics.
   */
  constantEquals = function constantEquals(x, y) {
    var result = true,
      length = y.length,
      i;

    for (i=0; i<length; i++) {
      if (x.charCodeAt(i) !== y.charCodeAt(i)) {
        result = false;
      }
    }
    return result;
  },

  /**
   * verify(hash, input, callback)
   *
   * Takes a stored hash, password input from the user,
   * and a callback, and determines whether or not the
   * user's input matches the stored password.
   *
   * @param  {[type]}   hash     stored password hash
   * @param  {[type]}   input    user's password input
   * @param  {Function} callback callback(err, isValid)
   */
  verify = function verify(hash, input, callback) {
    var oldHash = hash,
      salt = hash.slice(0, 88);

    pbkdf2.call(this, input, salt, function (err, newHash) {
      var result;
      if (err) {
        return callback(err);
      }
      callback(null, constantEquals(salt + '$' + newHash, oldHash));
    });
  },

  /**
   * configure(options)
   *
   * Alter defaults for `keylength` or `iterations`.
   * Warning: Decreasing these values can make your password
   * database less secure.
   *
   * @param  {Object} options Options object.
   * @param  {Number} options.keylength
   * @param  {Number} options.iterations
   * @return {Object}         credential object
   */
  configure = function configure(options) {
    var overrides = pick(options, ['keylength', 'iterations']);
    mixIn(this, overrides);
    return this;
  };

module.exports = {
  hash: toHash,
  verify: verify,
  configure: configure,
  keylength: 66,
  iterations: 80000
};
