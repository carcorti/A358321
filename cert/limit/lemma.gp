/* Carlo Corti: exact finite certificates for both prime divisors of15. */
P(k)=k*(17*k-15)/2;
for(k=0,8,if(P(k+9)-P(k)!=9*(17*k+69),error("period9")));
for(k=0,24,if(P(k+25)-P(k)!=25*(17*k+205),error("period25")));
forprime(p=3,5,for(k=0,p^2-1,if(P(k)%p==0 && P(k)%p^2!=0,error("valuation1"))));
print("mod9=",vector(9,i,P(i-1)%9));
print("mod25=",vector(25,i,P(i-1)%25));
print("EXACT_PREFIX_LEMMA_3_AND_5_PASS");
quit;
