<?php

### RGB >> HSL
function _color_rgb2hsl($rgb) {
  $r = $rgb[0]; $g = $rgb[1]; $b = $rgb[2];
  $min = min($r, min($g, $b)); $max = max($r, max($g, $b));
  $delta = $max - $min; $l = ($min + $max) / 2; $s = 0;
  if ($l > 0 && $l < 1) {
    $s = $delta / ($l < 0.5 ? (2 * $l) : (2 - 2 * $l));
  }
  $h = 0;
  if ($delta > 0) {
    if ($max == $r && $max != $g) $h += ($g - $b) / $delta;
    if ($max == $g && $max != $b) $h += (2 + ($b - $r) / $delta);
    if ($max == $b && $max != $r) $h += (4 + ($r - $g) / $delta);
    $h /= 6;
  } return array($h, $s, $l);
}

### HSL >> RGB
function _color_hsl2rgb($hsl) {
  $h = $hsl[0]; $s = $hsl[1]; $l = $hsl[2];
  $m2 = ($l <= 0.5) ? $l * ($s + 1) : $l + $s - $l*$s;
  $m1 = $l * 2 - $m2;
  return array(_color_hue2rgb($m1, $m2, $h + 0.33333),
               _color_hue2rgb($m1, $m2, $h),
               _color_hue2rgb($m1, $m2, $h - 0.33333));
}

### Helper function for _color_hsl2rgb().
function _color_hue2rgb($m1, $m2, $h) {
  $h = ($h < 0) ? $h + 1 : (($h > 1) ? $h - 1 : $h);
  if ($h * 6 < 1) return $m1 + ($m2 - $m1) * $h * 6;
  if ($h * 2 < 1) return $m2;
  if ($h * 3 < 2) return $m1 + ($m2 - $m1) * (0.66666 - $h) * 6;
  return $m1;
}

### Convert a hex color into an RGB triplet.
function _color_unpack($hex, $normalize = false) {
  if (strlen($hex) == 4) {
    $hex = $hex[1] . $hex[1] . $hex[2] . $hex[2] . $hex[3] . $hex[3];
  } $c = hexdec($hex);
  $out = [];
  for ($i = 16; $i >= 0; $i -= 8) {
    $out[] = (($c >> $i) & 0xFF) / ($normalize ? 255 : 1);
  } return $out;
}

### Convert an RGB triplet to a hex color.
function _color_pack($rgb, $normalize = false) {
  $out = 0;
  foreach ($rgb as $k => $v) {
    $out |= (($v * ($normalize ? 255 : 1)) << (16 - $k * 8));
  }return '#'. str_pad(dechex($out), 6, 0, STR_PAD_LEFT);
}

?>