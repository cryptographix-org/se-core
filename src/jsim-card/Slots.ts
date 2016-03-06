import { ByteArray } from 'cryptographix-sim-core';

class JSSimulatedSlot
{
  cardWorker;
  onAPDUResponse;
  stop;

  OnMessage(e)
  {
    if (this.stop) return;

    if (e.data.command == "debug")
    {
      console.log(e.data.data);
    }
    else if (e.data.command == "executeAPDU")
    {
      // console.log( new ByteString( e.data.data ).toString() );

      if ( this.onAPDUResponse )
      {
        var bs = <Uint8Array>e.data.data, len = bs.length;

        this.onAPDUResponse( ( bs[ len - 2 ] << 8 ) | bs[ len - 1 ], ( len > 2 ) ? new ByteArray( bs.subarray( 0, len-2 ) ) : null );
      }
    }
    else
    {
      console.log( "cmd: " + e.data.command + " data: " + e.data.data );
    }
  }

  init()
  {
    this.cardWorker = new Worker( "js/SmartCardSlotSimulator/SmartCardSlotWorker.js" );
    this.cardWorker.onmessage = this.OnMessage.bind( this );

    this.cardWorker.onerror = function(e: Event)
    {
      //alert( "Error at " + e.filename + ":" + e.lineno + ": " + e.message );
    }
  }

  sendToWorker( command, data )
  {
    this.cardWorker.postMessage(
      {
        "command": command,
        "data": data
      }
    );
  }

  executeAPDUCommand( bCLA, bINS, bP1, bP2, commandData, wLe, onAPDUResponse )
  {
    var cmd = [ bCLA, bINS, bP1, bP2 ];
    var len = 4;
    var bsCommandData = ( commandData instanceof ByteArray ) ? commandData : new ByteArray( commandData, ByteArray.HEX );
    if ( bsCommandData.length > 0 )
    {
      cmd[len++] = bsCommandData.length;
      for( var i = 0; i < bsCommandData.length; ++i )
        cmd[len++] = bsCommandData.byteAt( i );
    }
    else if ( wLe != undefined )
        cmd[len++] = wLe & 0xFF;

    this.sendToWorker( "executeAPDU", cmd );

    this.onAPDUResponse = onAPDUResponse;

    // on success/failure, will callback
    // if ( resp == null )
    return;
  }
}
