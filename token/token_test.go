package token

import (
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis"
	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"github.com/rrm80/gautham/serializer"
	"github.com/vmihailenco/msgpack"
)

var (
	redisServer *miniredis.Miniredis
	redisClient *redis.Client

	tToken    *Token
	tTokenBin []byte
	tFpIBin   []byte
	tFpCBin   []byte

	tSerlr serializer.Serializer
)

func init() {
	{
		tToken = New(uuid.New(),
			"https://auth-server.example.org",
			[]string{
				"https://app0.example.org",
				"https://3rdparty-server.example.com",
				"proto://48.49.50.51/resource?query=foo",
			},
			365*24*time.Hour)
	}

	{
		var err error
		if tTokenBin, err = msgpack.Marshal(tToken); nil != err {
			panic(err)
		}
	}

	{
		var err error
		tToken.fpi = makeFootprint(0, "91.92.93.94",
			"https://app0.example.org/login", "https://app0.example.org",
			"Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0")
		if tFpIBin, err = msgpack.Marshal(tToken.fpi); nil != err {
			panic(err)
		}
	}

	{
		var err error
		tToken.fpc = makeFootprint(time.Now().Add(24*time.Hour).Unix(),
			"199.198.197.196", "https://app0.example.org/resource#foo",
			"https://app0.example.org",
			"Mozilla/5.0 (Linux; Android 7.0; Pixel C Build/NRD90M; wv) "+
				"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "+
				"Chrome/52.0.2743.98 Safari/537.36")
		if tFpCBin, err = msgpack.Marshal(tToken.fpc); nil != err {
			panic(err)
		}
	}

	{
		var err error
		if tSerlr, err = serializer.New(
			serializer.SignNone, nil, 0); nil != err {
			panic(err)
		}
	}
}

func TestMain(m *testing.M) {
	var err error
	var n int

	// set up miniredis instance
	if redisServer, err = miniredis.Run(); nil != err {
		panic(err)
	}

	// construct, connect and ping from the a redis client to miniredis instance
	redisClient = redis.NewClient(&redis.Options{
		Addr: redisServer.Addr(),
	})

	if err = redisClient.Ping().Err(); nil != err {
		panic(err)
	}

	// run the tests
	n = m.Run()

	// try to gracefully close the redis client connection
	if err = redisClient.Close(); nil != err {
		panic(err)
	}

	// gracefully close the miniredis instance
	redisServer.Close()
	os.Exit(n)
}

func BenchmarkTokenBin(b *testing.B) {
	b.Run("Enc", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := msgpack.Marshal(tToken); nil != err {
				b.Fatal(err)
			}
		}
	})

	b.Run("Dec", func(b *testing.B) {
		var tk *Token
		for i := 0; i < b.N; i++ {
			if err := msgpack.Unmarshal(tTokenBin, &tk); nil != err {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkFootprintBin(b *testing.B) {
	b.Run("Enc", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := msgpack.Marshal(tToken.fpi); nil != err {
				b.Fatal(err)
			}
		}
	})

	b.Run("Dec", func(b *testing.B) {
		var fp *Footprint
		for i := 0; i < b.N; i++ {
			if err := msgpack.Unmarshal(tFpIBin, &fp); nil != err {
				b.Fatal(err)
			}
		}
	})
}
