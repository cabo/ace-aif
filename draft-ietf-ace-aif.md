---
title: An Authorization Information Format (AIF) for ACE
abbrev: ACE AIF
docname: draft-ietf-ace-aif-latest
# date: 2021-06-24

stand_alone: true

ipr: trust200902
area: Internet
wg: ACE Working Group
kw: Internet-Draft
cat: info

pi:
  toc: yes
  tocdepth: 4
  sortrefs: yes
  symrefs: yes

author:
      -
        ins: C. Bormann
        name: Carsten Bormann
        org: Universität Bremen TZI
        street: Postfach 330440
        city: Bremen
        code: D-28359
        country: Germany
        phone: +49-421-218-63921
        email: cabo@tzi.org

normative:
  RFC7252: coap
  RFC8126: ianacons
  RFC8610: cddl

informative:
  RFC4949: gloss
  RFC8259: json
  I-D.ietf-ace-oauth-authz: ace-oauth
#  I-D.ietf-ace-dtls-authorize: dtls-ace
#  I-D.ietf-ace-oscore-profile: oscoap-ace
  RFC7493: i-json
  RFC8949: cbor
  RFC8132: patch
  RFC8576: seccons
  RFC6570: uri-templates
  RFC7228: term

--- abstract

Constrained Devices as they are used in the "Internet of Things" need
security.
One important element of this security is that devices in the Internet
of Things need to be able to decide which operations requested of them
should be considered authorized, need to ascertain that the
authorization to request the operation does apply to the actual
requester,
and need to ascertain that other devices they place
requests on are the ones they intended.

To transfer detailed authorization information from an authorization manager
(such as an ACE-OAuth Authorization Server) to a device, a
compact representation format is needed.
This document provides a suggestion for such a format, the
Authorization Information Format (AIF).
AIF is defined both as a general structure that can be used for many
different applications and as a specific refinement that describes
REST resources (potentially dynamically created) and the permissions on them.

--- middle

Introduction
============


Constrained Devices as they are used in the "Internet of Things" need
security.
One important element of this security is that devices in the Internet
of Things need to be able to decide which operations requested of them
should be considered authorized, need to ascertain that the
authorization to request the operation does apply to the actual
requester,
and need to ascertain that other devices they place
requests on are the ones they intended.

To transfer detailed authorization information from an authorization manager
(such as an ACE-OAuth Authorization Server {{-ace-oauth}}) to a device, a
compact representation format is needed.
This document provides a suggestion for such a format, the
Authorization Information Format (AIF).
AIF is defined both as a general structure that can be used for many
different applications and as a specific refinement that describes
REST resources (potentially dynamically created) and the permissions on them.

Terminology
-----------

This memo uses terms from {{-coap}} and {{-gloss}}; CoAP is used for
the explanatory examples as it is a good fit for Constrained Devices.

The shape of data is specified in CDDL {{-cddl}}.
Terminology for Constrained Devices is defined in {{-term}}.

{::boilerplate bcp14+-tagged}

(Note that this document is itself informational, but it is discussing
normative statements that MUST be put into concrete terms in each
specification that makes use of this document.)

The term "byte", abbreviated by "B", is used in its now customary
sense as a synonym for "octet".

Information Model
=================

Authorizations are generally expressed through some data structures
that are cryptographically secured (or transmitted in a secure way).
This section discusses the information model underlying the payload of
that data (as opposed to the cryptographic armor around it).

For the purposes of this specification, the underlying access control model
will be that of an access matrix, which gives a set of permissions for
each possible combination of a subject and an object.
We do not concern the AIF format with the subject for which the
AIF data item is issued, so we are focusing the AIF data item on a single row in the
access matrix (such a row traditionally is also called a capability list).
As a consequence, AIF MUST be used in a way that the subject of the
authorizations is unambiguously identified (e.g., as part of the armor
around it).

The generic model of such a capability list is a list of pairs of
object identifiers and the permissions the subject has on the
object(s) identified.

~~~ cddl
AIF-Generic<Toid, Tperm> = [* [Toid, Tperm]]
~~~
{: #genaif title="Definition of Generic AIF"}

In a specific data model, the object identifier (`Toid`) will often be
a text string, and the set of permissions (`Tperm`) will be represented
by a bitset in turn represented as a number (see {{data-model}}).

~~~ cddl
AIF-Specific = AIF-Generic<tstr, uint>
~~~
{: #specaif title="Likely shape of a specific AIF"}


REST-specific Model {#rest-model}
-------------------

In the specific instantiation of the REST resources and the
permissions on them, for the object identifiers (`Toid`), we
use the URI of a resource on a CoAP server.  More specifically, the
parts of the URI that identify the server ("authority" in
{{?RFC3986}}) are considered the realm of the authentication mechanism
(which are handled in the cryptographic armor); we therefore focus on
the "path-absolute" and "query" parts of the URI (URI "local-part" in
this specification, as expressed by the Uri-Path and Uri-Query options
in CoAP).  As a consequence, AIF MUST be used in a way that it is
clear who is the target (enforcement point) of these authorizations
(note that there may be more than one target that the same
authorization applies to, e.g., in a situation with homogeneous
devices).

For the permissions (`Tperm`), we simplify the model permissions to
giving the subset of the CoAP methods permitted.  This model is
summarized in {{im-example}}.

| local-part | Permission Set |
| /s/temp    | GET            |
| /a/led     | PUT, GET       |
| /dtls      | POST           |
{: #im-example title="An authorization instance in the AIF Information Model"}

In this example, a device offers a temperature sensor `/s/temp` for
read-only access and a LED actuator `/a/led` for read/write.


Limitations
-----------

This simple information model only allows granting permissions for
statically identifiable objects, e.g., URIs for the REST-specific
instantiation.  One might be tempted to extend the model towards URI
templates {{-uri-templates}} (for instance, to open up an
authorization for many parameter values as in
 `/s/temp{?any*}`), however, that requires some considerations of
the ease and unambiguity of matching a given URI against a set of
templates in an AIF object.

This simple information model also does not allow further
conditionalizing access based on state outside the identification of
objects (e.g., "opening a door is allowed if that is not locked").

Finally, the model does not provide any special access for a set of
resources that are specific to a subject, e.g., that the subject
created itself by previous operations (PUT, POST, or PATCH/iPATCH {{-patch}}) or that were
specifically created for the subject by others.

Extended REST-specific Model {#ext-rest-model}
----------------------------

The extended REST-specific model addresses the need to provide defined
access to dynamic resources that were created by the subject itself,
specifically, a resource that is made known to the subject by
providing Location-* options in a CoAP response or using the Location
header field in HTTP {{?RFC7231}} (the Location-indicating mechanisms).
(The concept is somewhat comparable to "ACL inheritance" in NFSv4
{{?RFC8881}}, except that it does not use a containment relationship
but the fact that the dynamic resource was created from a resource to
which the subject had access.)
In other words, it addresses the third limitation mentioned in {{limitations}}.

| local-part     | Permission Set                    |
| /a/make-coffee | POST, Dynamic-GET, Dynamic-DELETE |
{: #im-example-dynamic title="An authorization instance in the AIF Information Model"}

For a method X, the presence of a Dynamic-X permission means that the subject
holds permission to exercise the method X on resources that have been
returned by a Location-indicating mechanism to a request that the
subject made to the resource listed (`/a/make-coffee` in the example
shown in {{im-example-dynamic}},
which might return the location of a resource that allows GET to find
out about the status and DELETE to cancel the coffee-making
operation).

Since the use of the extension defined in this section can be detected
by the mentioning of the Dynamic-X permissions, there is no need for
another explicit switch between the basic and the extended model; the
extended model is always presumed once a Dynamic-X permission is present.

Data Model
==========

Different data model specializations can be defined for the generic
information model given above.

In this section, we will give the data model for basic REST
authorization as per {{rest-model}} and {{ext-rest-model}}.
As discussed, in this case the object identifier is specialized as a text string
giving a relative URI (local-part as absolute path on the server
serving as enforcement point).
The permission set is specialized to a single number by the following steps:

* The entries in the table that specify the same local-part are merged
  into a single entry that specifies the union of the permission sets.
* The (non-dynamic) methods in the permission sets are converted into
  their CoAP method numbers, minus 1.
* Dynamic-X permissions are converted into what the number would have
  been for X, plus a Dynamic-Offset chosen as 32 (e.g., 35 for Dynamic-DELETE).
* The set of numbers is converted into a single number by taking each
  number to the power of two and computing the inclusive OR of the
  binary representations of all the power values.

This data model could be interchanged in the JSON
{{-json}} representation given in {{dm-json}}.

~~~json
[["/s/temp", 1], ["/a/led", 5], ["/dtls", 2]]
~~~
{: #dm-json title="An authorization instance encoded in JSON (46 bytes)"}

In {{aif-cddl}}, a straightforward specification of the data model
(including both the methods from {{-coap}} and the new ones from
{{-patch}}, identified by the method code minus 1) is shown in CDDL {{-cddl}}:

~~~~ cddl
AIF-REST = AIF-Generic<path, permissions>
path = tstr   ; URI relative to enforcement point
permissions = uint .bits methods
methods = &(
  GET: 0
  POST: 1
  PUT: 2
  DELETE: 3
  FETCH: 4
  PATCH: 5
  iPATCH: 6
  Dynamic-GET: 32; 0 .plus Dynamic-Offset
  Dynamic-POST: 33; 1 .plus Dynamic-Offset
  Dynamic-PUT: 34; 2 .plus Dynamic-Offset
  Dynamic-DELETE: 35; 3 .plus Dynamic-Offset
  Dynamic-FETCH: 36; 4 .plus Dynamic-Offset
  Dynamic-PATCH: 37; 5 .plus Dynamic-Offset
  Dynamic-iPATCH: 38; 6 .plus Dynamic-Offset
)
~~~~
{: #aif-cddl title="AIF in CDDL"}

A representation of this information in CBOR
{{-cbor}} is given in {{dm-cbor}}; again, several
optimizations/improvements are possible.

~~~hex-dump
83                        # array(3)
   82                     # array(2)
      67                  # text(7)
         2f732f74656d70   # "/s/temp"
      01                  # unsigned(1)
   82                     # array(2)
      66                  # text(6)
         2f612f6c6564     # "/a/led"
      05                  # unsigned(5)
   82                     # array(2)
      65                  # text(5)
         2f64746c73       # "/dtls"
      02                  # unsigned(2)
~~~
{: #dm-cbor title="An authorization instance encoded in CBOR (28 bytes)"}

Note that choosing 32 as Dynamic-Offset means that all future CoAP
methods that can be registered can be represented both as themselves
and in the Dynamic-X variant, but only the dynamic forms of methods 1
to 21 are typically usable in a JSON form {{-i-json}}.

Media Types
===========

This specification defines media types for the generic information
model, expressed in JSON (`application/aif+json`) or in CBOR (`application/aif+cbor`).  These media types have
parameters for specifying `Toid` and `Tperm`; default values are the
values "local-uri" for `Toid` and "REST-method-set" for `Tperm`.

A specification that wants to use Generic AIF with different `Toid`
and/or `Tperm` is expected to request these as media type parameters
({{registries}}) and register a corresponding Content-Format ({{content-format}}).

IANA Considerations
===================

Media Types
-----------

IANA is requested to add the following Media-Types to the "Media Types" registry.

| Name     | Template             | Reference                 |
| aif+cbor | application/aif+cbor | RFC XXXX, {{media-types}} |
| aif+json | application/aif+json | RFC XXXX, {{media-types}} |
{: align="left"}

// RFC Ed.: please replace RFC XXXX with this RFC number and remove this note.

For `application/aif+cbor`:

{: spacing="compact"}
Type name:
: application

Subtype name:
: aif+cbor

Required parameters:
: * `Toid`: the identifier for the object for which permissions are
    supplied.
    A value from the subregistry for `Toid`.
    Default value: "local-uri" (RFC XXXX).

  * `Tperm`: the data type of a permission set for the the object
    identified via a `Toid`.
    A value from the subregistry for `Tperm`.
    Default value: "REST-method-set" (RFC XXXX).

Optional parameters:
: none

Encoding considerations:
: binary (CBOR)

Security considerations:
: {{seccons}} of RFC XXXX

Interoperability considerations:
: none

Published specification:
: {{media-types}} of RFC XXXX

Applications that use this media type:
: No known applications currently use this media type.

Fragment identifier considerations:
: The syntax and semantics of fragment identifiers is as specified for
  "application/cbor".  (At publication of RFC XXXX, there is no
  fragment identification syntax defined for "application/cbor".)

Person & email address to contact for further information:
: ACE WG mailing list (ace@ietf.org),
  or IETF Applications and Real-Time Area (art@ietf.org)

Intended usage:
: COMMON

Restrictions on usage:
: none

Author/Change controller:
: IETF

Provisional registration:
: no


For `application/aif+json`:

{: spacing="compact"}
Type name:
: application

Subtype name:
: aif+json

Required parameters:
: * `Toid`: the identifier for the object for which permissions are
    supplied.
    A value from the subregistry for `Toid`.
    Default value: "local-uri" (RFC XXXX).

  * `Tperm`: the data type of a permission set for the the object
    identified via a `Toid`.
    A value from the subregistry for `Tperm`.
    Default value: "REST-method-set" (RFC XXXX).

Optional parameters:
: none

Encoding considerations:
: binary (JSON is UTF-8-encoded text)

Security considerations:
: {{seccons}} of RFC XXXX

Interoperability considerations:
: none

Published specification:
: {{media-types}} of RFC XXXX

Applications that use this media type:
: No known applications currently use this media type.

Fragment identifier considerations:
: The syntax and semantics of fragment identifiers is as specified for
  "application/json".  (At publication of RFC XXXX, there is no
  fragment identification syntax defined for "application/json".)

Person & email address to contact for further information:
: ACE WG mailing list (ace@ietf.org),
  or IETF Applications and Real-Time Area (art@ietf.org)

Intended usage:
: COMMON

Restrictions on usage:
: none

Author/Change controller:
: IETF

Provisional registration:
: no



Registries
----------

IANA is requested to create a registry for AIF with two sub-registries for `Toid` and `Tperm`,
populated with:

| Subregistry | name            | Description/Specification                                |
|-------------|-----------------|----------------------------------------------------------|
| Toid        | local-part      | local-part of URI as specified in RFC XXXX               |
| Tperm       | REST-method-set | set of REST methods represented as specified in RFC XXXX |

The registration policy is Specification required {{-ianacons}}.
The designated expert will engage with the submitter to ascertain the
requirements of this document are addressed.

// RFC Ed.: please replace RFC XXXX with this RFC number and remove this note.

Content-Format
--------------

IANA is requested to register Content-Format numbers in the "CoAP
Content-Formats" subregistry, within the "Constrained RESTful
Environments (CoRE) Parameters" Registry {{?IANA.core-parameters}}, as
follows:

| Media Type           | Content Coding | ID   | Reference |
| application/aif+cbor | -              | TBD1 | RFC XXXX  |
| application/aif+json | -              | TBD2 | RFC XXXX  |
{: align="left"}

// RFC Ed.: please replace TBD1 and TBD2 with assigned IDs and remove this note.
// RFC Ed.: please replace RFC XXXX with this RFC number and remove this note.

Note that applications that register `Toid` and `Tperm` values are
encouraged to also register Content-Formats for the relevant
combinations.


Security Considerations {#seccons}
=======================

The security considerations of {{-coap}} apply.
Some wider issues are discussed in {{-seccons}}.

When applying these formats, the referencing specification must be
careful to:

* ensure that the cryptographic armor employed around this format
  fulfills the security objectives, and that the armor or some
  additional information included in it with the AIF information
  unambiguously identifies the subject to which the authorizations
  shall apply, and

* ensure that the types used for `Toid` and `Tperm` provide the
  appropriate granularity so that application requirements on the
  precision of the authorization information are fulfilled, and that
  all parties understand `Toid`/`Tperm` pairs to signify the same operations.

For the data formats, the security considerations of {{-json}} and
{{-cbor}} apply.

A generic implementation of AIF might implement just the basic REST
model as per {{rest-model}}.  If it receives authorizations that
include permissions that use the {{ext-rest-model}}, it needs to either
reject the AIF data item entirely or act only on the
permissions that it does understand.  In other words, the usual
principle "everything is denied until it is explicitly allowed" needs
to hold here as well.

--- back

Acknowledgements
================
{: numbered="no"}

{{{Jim Schaad}}},
{{{Francesca Palombini}}},
{{{Olaf Bergmann}}},
{{{Marco Tiloca}}},
and
{{{Christian Amsüss}}}
provided comments that shaped the
direction of this document.
{{{Alexey Melnikov}}} pointed out that there were gaps in the media
type specifications, and {{{Loganaden Velvindron}}} provided a shepherd
review with further comments.

--- fluff

<!--  LocalWords:  cryptographically cryptographic strawman URI CoAP
 -->
<!--  LocalWords:  AIF unambiguity conditionalizing JSON CBOR
 -->
<!--  LocalWords:  optimizations instantiation
 -->
