# Derivation of cummulative integer average

## Formula in exact precision (infinite precision)

$    \bar{x}_n \;\;\; = \frac{1}{n} \sum_{i=1}^n{x_i}    $

$    \bar{x}_{n+1} = \frac{1}{n+1} \sum_{i=1}^{n+1}{x_i}    $  
$    \qquad\; = \frac{1}{n+1} ( n \bar{x}_n + x_{n+1} )    $  
$    \qquad\; = \frac{1}{n+1} (\; (n+1) \bar{x}_n - \bar{x}_n + x_{n+1} \;)    $  
$    \qquad\; = \bar{x}_n + \frac{1}{n+1} (\; x_{n+1} - \bar{x}_n \;)    $

## Formula in integer arithmetic

$    \bar{x}_n \;\;\; = q_n + \frac{r_n}{n} \qquad \text{where } q_n,\; r_n \text{ are the quotient, remainder respectively}    $

$    \bar{x}_{n+1} = ( q_n + \frac{r_n}{n} ) + \frac{1}{n+1} (\, x_{n+1} - ( q_n + \frac{r_n}{n} ) \,)    $  
$    \qquad\; = q_n + \frac{(n+1)\,r_n}{(n+1)\,n} + \frac{1}{n+1} (x_{n+1} - q_n - \frac{r_n}{n} )    $  
$    \qquad\; = q_n + \frac{1}{n+1} (\, x_{n+1} - q_n - \frac{r_n}{n} + \frac{(n+1)\,r_n}{n} \,)    $  
$    \qquad\; = q_n + \frac{1}{n+1} ( x_{n+1} - q_n + r_n )    $

$    \text{Let } a_{n+1},\; b_{n+1} \text{ be the quotient, remainder of } \frac{1}{n+1} ( x_{n+1} - q_n + r_n ) \text{ respectively}    $  
$    q_{n+1} \, = q_n + a_{n+1}    $  
$    r_{n+1} \, = b_{n+1}    $

## Reference
https://www.codeproject.com/Articles/807195/Precise-and-safe-calculation-method-for-the-averag  
- Does not explain how the formula was derived