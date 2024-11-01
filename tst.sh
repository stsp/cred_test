sudo adduser test
sudo chown test:test client
sudo chmod ug+s client
sudo chown root:root server
sudo chmod ug+s server
./server &
sleep 1
./client
