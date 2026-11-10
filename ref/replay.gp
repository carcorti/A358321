omega_polygonals(A, B, n, k) = A=max(A, vecprod(primes(n))); (f(m, p, j) = my(list=List()); forprime(q=p, sqrtnint(B\m, j), my(v=m*q, r=nextprime(q+1)); while(v <= B, if(j==1, if(v>=A && ispolygonal(v,k), listput(list, v)), if(v*r <= B, list=concat(list, f(v, r, j-1)))); v *= q)); list); vecsort(Vec(f(1, 2, n)));
gettime(); v=omega_polygonals(1,82634328555218440,13,13); print("REPLAY n=13 K=122574155 Y=82634328555218440 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,2383985537862979050,14,14); print("REPLAY n=14 K=630341910 Y=2383985537862979050 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,239213805711830629680,15,15); print("REPLAY n=15 K=6066475415 Y=239213805711830629680 values=",v," gp_ms=",gettime());
quit
