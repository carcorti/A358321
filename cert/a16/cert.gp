/* Carlo Corti. Independent PARI exact arithmetic/factorization, no search. */
k = 119535945060;
v = k*(7*k-6);
if(v != 100021895128994153154840, error("polygon value mismatch"));
F = factor(v);
if(matsize(F)[1] != 16, error("distinct support mismatch"));
if(prod(i=1, matsize(F)[1], F[i,1]^F[i,2]) != v, error("factor product"));
for(i=1,matsize(F)[1],if(!isprime(F[i,1]),error("composite base")));
t = sqrtint(7*v+9);
if(t*t != 7*v+9 || (t+3)%7 != 0 || (t+3)/7 != k, error("inverse"));
print("k=", k);
print("factor(k)=", factor(k));
print("factor(7*k-6)=", factor(7*k-6));
print("P16(k)=",v);
print("factor(P16(k))=",F);
print("omega(P16(k))=",omega(v));
print("PARI_CERTIFICATE_PASS");
quit;
