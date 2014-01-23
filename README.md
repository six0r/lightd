lightd
======

lightd is a simple HTTP gateway for the lifx binary protocol

#### Requirements

- command line PHP binary (>= 5.4)
- configured lifx bulbs with fixed address or hostname

lightd tries to connect to the lifx gateway bulb using hostname "lifx" and port
56700 and provides its REST API on port 5439, you may change these values at
the top of lightd.php

if everything is set up correctly, you should see something like this when you
run lightd from the command line :

```
20140123:204248 lightd/0.9.0 (c) 2014 by sIX / aEGiS
20140123:204248 loaded 5 patterns
20140123:204248 connected to lifx
20140123:204248 API server listening on port 5439
20140123:204248 found gateway bulb at d073d5014736
20140123:204248 new bulb registered: Kitchen
20140123:204249 new bulb registered: Living
```

you may want to create a startup script and redirect the standard output to a
log file if you wish to run it long term.

#### API methods

##### Power on/off

```
/power/(on|off)[/<bulb label>]
```

if bulb_label is not given, the command applies to all bulbs in the lifx mesh

examples:
* /power/on/Kitchen
* /power/off

##### Set color

```
/color/<color>[K<temperature][/<bulb label>]
```

if bulb_label is not given, the color is applied to all bulbs in the lifx mesh

examples:
* /color/ffffff/Kitchen
* /color/404040K3500/Living
* /color/002040

##### Set pattern

```
/pattern/<name>[/<transition_time_ms>]
```

patterns are read from the patterns.ini file
if transition_time_ms is not given, the pattern is applied immediately

examples:
* /pattern/off
* /pattern/movies/10000
* /pattern/night/3600000

##### Dump state

```
/state
```

dumps a JSON encoded array of bulb objects with their current state
