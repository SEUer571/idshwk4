@load base/frameworks/sumstats

global all_count = 0;
global sum:table[addr] of count = table();

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="idshwk4", $apply=set(SumStats::UNIQUE,SumStats::SUM));
	SumStats::create([$name="404count", $epoch=10min, $reducers=set(r1),
					  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = 
					  {
					  		local r = result["idshwk4"];
					  		if(r$num>2)
					  		{
					  			if((r$num/sum[key$host])>0.2)
					  			{
					  				if((r$unique/r$num)>0.5)
					  					{
					  					print fmt("%s is a scanner with %d scan attempts on %d urls",key$host,r$num,r$unique);
					  				}
					  			}
					  		}
                                                                                                                sum[key$host] = 0;
					  }]);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
                if(c$id$orig_h in sum) {
		sum[c$id$orig_h] += 1;
	}
	else {
		sum[c$id$orig_h] = 1;
	}

	if(code==404)
	{
		SumStats::observe("idshwk4", [$host=c$id$orig_h], [$str=reason]);
	}
}