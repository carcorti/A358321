/* Carlo Corti: exact positive candidate certificate; no minimum search. */
k=153290693815740;
v=k*(17*k-15)/2;
F=factor(v);
if(matsize(F)[1]!=19,error("distinct prime count"));
if(prod(i=1,matsize(F)[1],F[i,1]^F[i,2])!=v,error("product"));
for(i=1,matsize(F)[1],if(!isprime(F[i,1]),error("composite")));
if(omega(v)!=19,error("omega"));
t=sqrtint(225+136*v);
if(t*t!=225+136*v || (t+15)%34 || (t+15)/34!=k,error("inverse"));
print("k=",k);
print("P19(k)=",v);
print("factor(P19(k))=",F);
print("omega(P19(k))=",omega(v));
print("PARI_POSITIVE_WITNESS_PASS; MINIMUM_NOT_PROVEN");
quit;
