name: Randy Thio
project: blockchain
requirements: must have at least 3 ports running

how to execute:
    - export FLASK_APP=blockchain.py
    - flask run --port 5000 or some other port 
        + important: must run on at least 3 ports or it will not work
        + verification requires more than the ones in the transaction
    
what routes to use and inputs as json:
    - '/nodes/register'
        + input example: {"nodes": ["localhost:5000", "localhost:5001"]}
    - '/book/new'
        + input example: {"title":"book1"}
    - '/book/request'
        + input example: {"title":"book1"}

how it works:
    - the requestor requests a book from the node that claims to own it. 
    The owner pings the other nodes in the network to verify his claim that 
    he is the owner by checking the end of their respective chain. After the sender is verified,
    the sender then sends the requestor the hash of the ownership - the block. The requestor then 
    shares the merged hash of the respective blockchain and the hash that he received to the other nodes.
    the other nodes verifies that the transaction is legitimate by recreating the hash sent by the requestor.
    the other nodes request the block the sender made to hash it and merge it with the hash of their respective chain
    to recreate the hash the requestor sent. If they are successful then the sender did relinquish his ownership to the 
    requestor and the requestor is now the owner of the book and everybody updates their blockchain.




