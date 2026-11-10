/* Carlo Corti. Independent PARI exact positive n18 certificate, no search. */
k = 4278672701330;
v = k*(8*k-7);
if(v != 146456320680822524361241890, error("polygon value mismatch"));
if(k*(16*k-14)/2 != v, error("generic polygon mismatch"));
F = factor(v);
if(matsize(F)[1] != 18, error("distinct support mismatch"));
if(prod(i=1, matsize(F)[1], F[i,1]^F[i,2]) != v, error("factor product"));
for(i=1,matsize(F)[1],if(!isprime(F[i,1]),error("composite base")));
t = sqrtint(196+128*v);
if(t*t != 196+128*v || (t+14)%32 != 0 || (t+14)/32 != k, error("inverse"));
print("k=", k);
print("factor(k)=", factor(k));
print("factor(8*k-7)=", factor(8*k-7));
print("P18(k)=",v);
print("factor(P18(k))=",F);
print("omega(P18(k))=",omega(v));
print("PARI_CERTIFICATE_PASS");
quit;
