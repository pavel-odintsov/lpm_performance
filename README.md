# patricia_performance
Test app for testing performance of https://github.com/MuriloChianfa/liblpm like I did for Patricia before: [here](https://pavel.network/making-35-000-000-ip-lookup-operations-per-second-with-patricia-tree/)

# Build LPM lib

```
cd repos
sudo apt install -y clang 
git clone git@github.com:MuriloChianfa/liblpm.git
mkdir build && cd build
cmake ..
make -j$(nproc)
```

# Build process

Then specify path to liblpm in CMakeLists.txt  

```
sudo apt install -y libboost-all-dev
git clone https://github.com/pavel-odintsov/patricia_performance
cd patricia_performance/src
mkdir build
cmake ..
make -j
```
