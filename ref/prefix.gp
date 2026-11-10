omega_polygonals(A, B, n, k) = A=max(A, vecprod(primes(n))); (f(m, p, j) = my(list=List()); forprime(q=p, sqrtnint(B\m, j), my(v=m*q, r=nextprime(q+1)); while(v <= B, if(j==1, if(v>=A && ispolygonal(v,k), listput(list, v)), if(v*r <= B, list=concat(list, f(v, r, j-1)))); v *= q)); list); vecsort(Vec(f(1, 2, n)));
gettime(); v=omega_polygonals(1,66,3,3); print("REPLAY n=3 K=11 Y=66 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,44100,4,4); print("REPLAY n=4 K=210 Y=44100 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,11310,5,5); print("REPLAY n=5 K=87 Y=11310 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,103740,6,6); print("REPLAY n=6 K=228 Y=103740 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,3333330,7,7); print("REPLAY n=7 K=1155 Y=3333330 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,185040240,8,8); print("REPLAY n=8 K=7854 Y=185040240 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,15529888374,9,9); print("REPLAY n=9 K=66612 Y=15529888374 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,626141842326,10,10); print("REPLAY n=10 K=395646 Y=626141842326 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,21647593547580,11,11); print("REPLAY n=11 K=2193303 Y=21647593547580 values=",v," gp_ms=",gettime());
gettime(); v=omega_polygonals(1,351877410344460,12,12); print("REPLAY n=12 K=8389010 Y=351877410344460 values=",v," gp_ms=",gettime());
quit
