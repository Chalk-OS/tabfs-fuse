#!/bin/bash
rm test.img && xmake -r make_test_img && xmake run -w . make_test_img test.img