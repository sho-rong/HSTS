open declarations

//ssl strip Attack
//non-use of HSTS
//ask to use HTTPS by redirection everytime when access with HTTP
run sslStrip{
	#HTTPClient=1
	#HTTPServer=2
	#HTTPIntermediary=1
	#Mallory=1
	#Alice=2
	
	some tr1,tr2,tr3,tr4,tr5,tr6:HTTPTransaction | {
		
	some s1,s2:HTTPServer | {
		
	one password:UserPassword | {
		
	//  tr1.req => tr2.req => tr2.resp => tr1.resp => tr3.req => tr4.req => tr4.resp => tr3.resp 
	// => tr5.req => tr6.req => tr6.resp => tr5.resp
	
	// HTTP connection  : tr1,tr2,tr3,tr5
	// HTTPS connection: tr4,tr6
	
	//tr1: user <-> intermediary
	tr1.req.from in HTTPClient
	tr1.req.to in HTTPIntermediary
	tr1.req.schema = HTTP
	tr1.resp.schema = HTTP
	
	//tr2: intermediary <-> Server1
	tr2.req.from in HTTPIntermediary
	tr2.req.to in s1
	tr2.req.schema = HTTP
	tr2.resp.schema  = HTTP 
	
	//tr3: intermediry <-> user
	tr3.req.from in HTTPIntermediary
	tr3.req.to in HTTPClient
	tr3.req.schema=HTTP
	tr3.resp.schema =HTTP
	
	//tr4: intermediary <-> Server
	tr4.req.from in HTTPIntermediary
	tr4.req.to in s2
	tr4.req.schema=HTTPS
	tr4.resp.schema=HTTPS
	
	//tr5: intermediary <-> user
	tr5.req.from in HTTPIntermediary
	tr5.req.to in HTTPClient
	password in tr5.req.body
	tr5.req.schema=HTTP
	tr5.resp.schema=HTTP

	//tr6: intermediary <-> Server
	tr6.req.from in HTTPIntermediary
	tr6.req.to in s2	
	tr6.req.schema=HTTPS
	password in tr6.req.body
	tr6.resp.schema=HTTPS
	
	//transaction's order
	happensBeforeOrdering[tr1.req,tr2.req]
	happensBeforeOrdering[tr2.resp,tr1.resp]
	tr1 in tr3.cause
	happensBeforeOrdering[tr3.req,tr4.req]
	happensBeforeOrdering[tr4.resp,tr3.resp]
	tr3 in tr5.cause
	happensBeforeOrdering[tr5.req,tr6.req] 
	happensBeforeOrdering[tr6.resp,tr5.resp]
	
	
	}
	}
	}
	
	some c:HTTPClient | c in Alice.httpClients
	some s:HTTPServer | s in Alice.servers
	all i:HTTPIntermediary | i in Mallory.servers
	
}for 6
