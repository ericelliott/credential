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
    // Add at least one character so that there's at least one thing to modulo over.
    a += " ";
    b += " ";
    var aLen = a.length,
        bLen = b.length,
        match = aLen === bLen ? 1 : 0,
        i = Math.max(aLen, bLen, MAX_KEY_CHARS);
    while (i--) {
      // We repeat the comparison over the strings with % so that we do not compare
      // a number to NaN, since that has different timing that comparing two numbers.
      match &= a.charCodeAt( i % aLen ) === b.charCodeAt( i % bLen ) ? 1 : 0;
    }
    return match === 1;
  }
};
