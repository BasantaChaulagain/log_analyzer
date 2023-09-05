rm enc/*
rm indexes/*
rm tmp/*
rm metadata

rm ../server/enc/*
rm ../server/indexes/*

echo {} > ltdict.json
echo {} > vdict.json

sed -i "s/last_cluster_id = [[:digit:]]\+/last_cluster_id = 0/g" config.ini

echo "Cleaning Successful!"