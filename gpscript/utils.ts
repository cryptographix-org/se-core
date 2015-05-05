export default class Hex
{
  private static decoder;

  static decode(a)
  {
    if ( Hex.decoder == undefined )
    {
      var hex = "0123456789ABCDEF";
      var allow = " \f\n\r\t\u00A0\u2028\u2029";
      var dec = [];
      for (var i = 0; i < 16; ++i)
          dec[hex.charAt(i)] = i;
      hex = hex.toLowerCase();
      for (var i = 10; i < 16; ++i)
          dec[hex.charAt(i)] = i;
      for (var i = 0; i < allow.length; ++i)
          dec[allow.charAt(i)] = -1;
      Hex.decoder = dec;
    }

    var out = [];
    var bits = 0, char_count = 0;
    for (var i = 0; i < a.length; ++i)
    {
      var c = a.charAt(i);
      if (c == '=')
          break;
      c = Hex.decoder[c];
      if (c == -1)
          continue;
      if (c == undefined)
          throw 'Illegal character at offset ' + i;
      bits |= c;
      if (++char_count >= 2) {
          out.push( bits );
          bits = 0;
          char_count = 0;
      } else {
          bits <<= 4;
      }
    }

    if (char_count)
      throw "Hex encoding incomplete: 4 bits missing";

    return out;
  }
}
