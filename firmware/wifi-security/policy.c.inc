/* SPDX-License-Identifier: MIT
 * The cipher arguments are the driver's selected enum values, not RSN offer
 * bitmasks. wpa_config_profile selects one protocol before wpa_set_bss runs.
 */
static int home_wifi_cipher_allowed(unsigned cipher)
{
    return cipher == WIFI_CIPHER_TYPE_CCMP ||
           cipher == WIFI_CIPHER_TYPE_GCMP ||
           cipher == WIFI_CIPHER_TYPE_GCMP256;
}

static int home_wifi_security_allowed(unsigned proto, unsigned pairwise,
                                      unsigned group)
{
    return proto == WPA_PROTO_RSN && home_wifi_cipher_allowed(pairwise) &&
           home_wifi_cipher_allowed(group);
}
