# Replace tcpflow to include in sguil interface.

@load base/frameworks/notice
@load base/utils/site
@load base/protocols/dns

# Turn on UDP content delivery.
redef udp_content_deliver_all_resp = T &redef;
redef udp_content_deliver_all_orig = T &redef;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
		print fmt("%s: %s", name, value);
	}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
		print fmt("%s.%d-%s.%d: %s %s", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p, code, reason);
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
		print fmt("%s", data);
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
		print fmt("%s.%d-%s.%d: %s %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, method, original_URI);
	}

event udp_contents(u: connection, is_orig: bool, contents: string)
	{
		if (is_orig)
	        {
        		print fmt("%s.%d-%s.%d: %s", u$id$orig_h, u$id$orig_p, u$id$resp_h, u$id$resp_p, "Bro UDP output from SRC:");
	        }
    		else
	        {
        		print fmt("%s.%d-%s.%d: %s", u$id$resp_h, u$id$resp_p, u$id$orig_h, u$id$orig_p, "Bro UDP output from DST:");
	        }
    		print fmt("%s",contents);
		print "";
	}

event dns_end(c: connection, msg: dns_msg)
        {
        	if ( c?$dns && c$dns$saw_reply && c$dns$saw_query )
		{
        		print fmt("%s.%d-%s.%d: %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, "Bro DNS analyzer output:");
			print "";
        	        print c$dns;
                }
        }
