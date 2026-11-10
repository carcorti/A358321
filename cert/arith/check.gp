/* Carlo Corti: independent modular certificate; no production search. */
P(k)=k*(17*k-15)/2;
V=vector(9,i,P(i-1)%9);
if(V!=[0,1,1,0,7,4,0,4,7],error("residue table"));
for(k=0,8,if(P(k+9)-P(k)!=9*(17*k+69),error("period")));
for(i=1,9,if(V[i]==3 || V[i]==6,error("v3=1 allowed")));
for(k=0,8,if(P(k)%3!=k^2%3,error("mod3 identity")));
print("P19_mod9=",V);
print("EXACT_UNIT0_EXCLUSION_PASS; NATIVE_JOB_UNCHANGED");
quit;
