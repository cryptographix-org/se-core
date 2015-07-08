import ByteString from "./byte-string";
import TLV from "./tlv";

export default class TLVList
{
  _tlvs: TLV[];

  constructor( tlvStream: ByteString, encoding?: number )
  {
    this._tlvs = [];

    var off = 0;

    while( off < tlvStream.length )
    {
      var tlvInfo = TLV.parseTLV( new ByteString( tlvStream._bytes.subarray( off ) ), encoding )

      if ( tlvInfo == null )
      {
        // error ...
        break;
      }
      else
      {
        // no more ... ?
        if ( tlvInfo.valueOffset == 0 )
          break;

        this._tlvs.push( new TLV( tlvInfo.tag, tlvInfo.value, encoding ) );
        off += tlvInfo.valueOffset + tlvInfo.len;
      }
    }
  }

  index( /*Number*/ index )
  {
    return this._tlvs[ index ];
  }
}
