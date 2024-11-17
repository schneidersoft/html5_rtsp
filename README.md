# html5_rtsp

This project is a fork of streamedian with the caveat that it works right out of the box.

The project consists of two parts. A javascipt client library to display rtsp streams in the browser and a C backend that will serve rtsp streams over websockets.

The operation is quite simple. The web browser opens two websocket connections with the server. The first is a control port and is used to control the stream, the second is a data port used exclusively for stream data.

The browser then requests that the server proxy to some rtsp camera. It then speaks rtsp directly with that camera.

Once the stream is started the server seperates the interleaved data payload from the rtsp stream and passes it to the browser data port.

# Demo

To simplify the demo podman or docker is used to launch both the webserver and websocket proxy

The two parts must be started in order.

## network

```
make network
```

## websocket proxy

Frst build the web socket proxy

```
make
```

Then build and run the web socket proxy container

```
make container
make wsp
```

## web frontend

in another shell launch the web frontend

```
make web
```

you should now be able to browse to http://localhost:8080 and see a webpage

# changing the rtsp streaming url

The rtsp streaming URL is set in index.html and must be availible to the websocket proxy. fi. a locally connected rtsp cammera.

```
const source = 'rtsp://192.168.1.13/main';
```

alternatively gst-rtsp-server comes with the utility 'test-launch' that can create an rtsp stream.

./test-launch --port 8888 "( videotestsrc ! x264enc ! rtph264pay name=pay0 pt=96 )"

You will need to adjust the URL in index.html to rtsp://your rtsp server ip:and port/test