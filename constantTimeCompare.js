  /**
   * constantTimeCompare(x, y)
   *
   *  Created by Eric Elliott for the book,
   *  Programming JavaScript Applications" (O'Reilly)
   *
   * MIT license http://opensource.org/licenses/MIT
   */
  
// Regardless of the string size the number of character iterations/comparisons
// ought to be equal to or higher than the maximum string size.
var MAX_KEY_CHARS = 1024;

  /*
   * Compare two strings, x and y with a constant-time
   * algorithm to prevent attacks based on timing statistics.
   *
   * This really ought to be in C; see:
   *     https://github.com/joyent/node/issues/8560
   *     http://stackoverflow.com/questions/18476402
   *
   * See also:
   *     http://jsperf.com/constant-time-string-comparison
   *     
   * @param  {String} x
   * @param  {String} y
   * @return {Boolean}
   */
module.exports = function constantTimeCompare(a, b) {
  // Using with{} nixes some V8 optimizations that would otherwise undermine
  // our intentions here.
  with({}) {
    var aLen = a.length,
        bLen = b.length,
        match = 0,
        i = Math.max(aLen, bLen, MAX_KEY_CHARS);
    // If the lengths don't match, the string doesn't match
    if (aLen !== bLen) {
      return false;
    }
    while (i--) {
      match |= a.charCodeAt( i ) ^ b.charCodeAt( i );
    }
    return match === 0;
  }
};
