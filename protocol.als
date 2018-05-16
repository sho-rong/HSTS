open declarations

//ssl strip Attack
//non-use of HSTS
//ask to use HTTPS by redirection everytime when access with HTTP
run sslStrip{
	#HTTPClient=1
	#HTTPServer=1
	#HTTPInternediary=1
	#Mallory=1
	#Alice=1
	
	some tr1,tr2,tr3,tr4,tr5,tr6:HTTPTransaction | {
	//  tr1.req => tr2.req => tr2.res => tr1.res => tr3.req => tr4.req => tr4.res => tr3.res 
	// => tr5.req => tr6.req => tr6.res => tr5.res
	
	// HTTP connection  : tr1,tr2,tr3,tr5
	// HTTPS connection: tr4,tr6
	
	//tr1: user <-> intermediary
	tr1.request.from in HTTPClient
	tr1.request.to in HTTPIntermediary
	tr1.request.schema = HTTP
	tr1.response.schema = HTTP
	
	//tr2: intermediary <-> Server
	tr2.request.from in HTTPIntermediary
	tr2.requset.to in HTTPServer
	tr2.request.schema = HTTP
	tr2.response.schema  = HTTP 
	
	//tr3: intermediry <-> user
	tr3.request.from in HTTPIntermediary
	tr3.request.to in HTTPClient
	tr3.request.schema=HTTP
	tr3.response.schema =HTTP
	
	//tr4: intermediary <-> Server
	tr4.request.from in HTTPIntermediary
	tr4.request.to in HTTPServer
	tr4.request.schema=HTTPS
	tr4.response.schema=HTTPS
	
	//tr5: intermediary <-> user
	tr5.request.from in HTTPIntermediary
	tr5.request.to in HTTPClient
	tr5.request.schema=HTTP
	tr5.response.schema=HTTP

	//tr6: intermediary <-> Server
	tr6.request.from in HTTPIntermediary
	tr6.request.to in HTTPServer	
	tr6.request.schema=HTTPS
	tr6.response.schema=HTTPS
	
	//transaction's order
	happensBeforeOrdering[tr1.request,tr2.request]
	happensBeforeOrdering[tr2.response,tr1.response]
	tr1 in tr3.cause
	happensBeforeOrdering[tr3.request,tr4.request]
	happensBeforeOrdering[tr4.response,tr3.response]
	tr3 in tr5.cause
	happensBeforeOrdering[tr5.request,tr6.request] 
	happensBeforeOrdering[tr6.response,tr5.response]
	
	//tampering with HTTPResponse by Attacker
	//link such as https://login.example.com->http://login.example.com
	link.ref.schema in tr2.response.body != link.ref.schema in tr1.response.body 
	
	}
	
	
}
