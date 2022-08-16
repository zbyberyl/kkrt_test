\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
log2(x) = log(x)/log(2);
\\ Pr[ Binom = k ]
bdist_(n,k,p)    = 0.0+binomial(n,k)*(p^k)*(1-p)^(n-k);
build_bdist_table(n,m) = {
    bdist_tbl = vector(201);
    p = 1/m;
    for(k=0,200,
        bdist_tbl[k+1] = bdist_(n,k,p)
    );
}
\\ Pr[ Binom = i ]
bdist(k) = bdist_tbl[k+1]
\\ Pr[ Binom = i ]
bdistleq(k) = sum(i=0,k, bdist(i))
\\ Pr[ Lap <= d ]
eps = 1
lapleq(d) = if(d<0, exp(eps*d)/2, 1 - exp(-eps*d)/2)
\\ Pr[ Binom <= k AND Binom + Lap <= d ]
\\ Pr[ Binom <= k AND         Lap <= d-Binom ]
bothevents(k,d) = sum(B=0,k, bdist(B) * lapleq(d-B))
\\   Pr[ B <= k | B + Lap <= d ]
\\ = Pr[ B <= k AND B + Lap <= d ] / Pr[ B + Lap <= d ]
\\                                      computed as B<=200 AND ...
conditional(k,d) = bothevents(k,d) / bothevents(200,d)
posterior(d,lambda) = {
    k = 1;
    while( log2(1 - conditional(k,d)) > -lambda,
        k = k+1
    );
    return(k-1);
}
nicetable(lambda) = {
    print("bayesian corrections for eps = ", eps);

    mina = -10;
    maxa = 50;

    write1("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18/output.txt",
    "Lookup{" n ", " floor(m) ", " eps ", " mina ", {");
    

    for(i=mina, maxa,
        needed = posterior(i,lambda);
        print(i, " => ", needed);

        write1("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18//output.txt", needed );

        if(i < maxa,
            write1("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18/output.txt", ", ");
        );
    );



    write("C:/Users/Peter/repo/libPSI/libPSI/MPSI/Grr18//output.txt", "}},")
}
\\\\\\\\\\\\\\\\\\\\
\\\\\\\\\\\\\\\\\\\\
\\\\\\\\\\\\\\\\\\\\
allocatemem();
\\n = 2^20;
\\m = n/4;

lambda = 40;
print("all calculations for n = ", n, "; m = ", m, "; lambda = ", lambda);
build_bdist_table(n,m); \\ takes a long time

\\eps=0.2; nicetable(lambda + log2(m))
eps=0.01; nicetable(lambda + log2(m))
\\eps=0.05; nicetable(lambda + log2(m))
\\eps=0.005; nicetable(lambda + log2(m))
\\eps=4; nicetable(lambda + log2(m))
