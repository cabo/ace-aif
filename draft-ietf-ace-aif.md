---
title: An Authorization Information Format (AIF) for ACE
abbrev: ACE AIF
docname: draft-ietf-ace-aif-latest
# date: 2022-02-14

stand_alone: true

ipr: trust200902
area: Internet
wg: ACE Working Group
kw: Internet-Draft
cat: std
consensus: true
submissiontype: IETF

pi:
  toc: yes
  tocdepth: 4
  sortrefs: yes
  symrefs: yes

venue:
  group: Authentication and Authorization for Constrained Environments (ace)
  mail: ace@ietf.org
  github: cabo/ace-aif

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
  RFC3986: uri
  RFC7252: coap
  I-D.ietf-httpbis-semantics: http-semantics
  RFC8126: ianacons
  RFC6838: media-type-reg
  RFC8610: cddl
  RFC9165: cddlplus

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
  IANA.core-parameters:
  IANA.media-type-sub-parameters:
  KebabCase:
    target: http://wiki.c2.com/?KebabCase
    title: KebabCase
    date: 2014-08-29

--- abstract

Information about which entities are authorized to perform what
operations on which constituents of other entities is a crucial
component of producing an overall system that is secure.  Conveying
precise authorization information is especially critical in highly
automated systems with large numbers of entities, such as the
"Internet of Things".

This specification provides a generic information model and format for
representing such authorization information, as well as two variants
of a specific instantiation of that format for use with REST resources
identified by URI path.

[^intro1-]: Constrained Devices as they are used in the "Internet of Things" need
    security in order to operate correctly and prevent misuse.
    One important element of this security is that devices in the Internet
    of Things need to be able to decide which operations requested of them
    should be considered authorized, need to ascertain that the
    authorization to request the operation does apply to the actual
    requester as authenticated,
    and need to ascertain that other devices they make
    requests of are the ones they intended.

[^intro2-]: This document defines such a format, the
    Authorization Information Format (AIF).
    AIF is defined both as a general structure that can be used for many
    different applications and
    as a specific instantiation tailored to REST resources and the permissions
    on them, including some provision for dynamically created resources.

--- middle

Introduction
============

[^intro1-]

To transfer detailed authorization information from an authorization manager
(such as an ACE-OAuth Authorization Server {{-ace-oauth}}) to a device, a
compact representation format is needed.
[^intro2-]

Terminology
-----------

This memo uses terms from CoAP {{-coap}} and the Internet Security Glossary {{-gloss}}; CoAP is used for
the explanatory examples as it is a good fit for Constrained Devices.

The shape of data is specified in CDDL {{-cddl}} {{-cddlplus}}.
Terminology for Constrained Devices is defined in {{-term}}.

{::boilerplate bcp14-tagged}

The term "byte", abbreviated by "B", is used in its now customary
sense as a synonym for "octet".

Information Model
=================

Authorizations are generally expressed through some data structures
that are cryptographically secured (or transmitted in a secure way).
This section discusses the information model underlying the payload of
that data (as opposed to the cryptographic armor around it).

The semantics of the authorization information defined in this
document are that of an *allow-list*:
everything is denied until it is explicitly allowed.

For the purposes of this specification, the underlying access control model
will be that of an access matrix, which gives a set of permissions for
each possible combination of a subject and an object.
We are focusing the AIF data item on a single row in the access matrix
(such a row has often been called a capability list), without
concern to the subject for which the data item is issued.
As a consequence, AIF MUST be used in a way that the subject of the
authorizations is unambiguously identified (e.g., as part of the armor
around it).

The generic model of such a capability list is a list of pairs of
object identifiers (of type `Toid`) and the permissions (of type `Tperm`) the subject has on the
object(s) identified.

~~~ cddl
AIF-Generic<Toid, Tperm> = [* [Toid, Tperm]]
~~~
{: #genaif title="Definition of Generic AIF"}

In a specific data model (such as the one also specified in
this document), the object identifier (`Toid`) will often be
a text string, and the set of permissions (`Tperm`) will be represented
by a bitset in turn represented as a number (see {{data-model}}).

~~~ cddl
AIF-Specific = AIF-Generic<tstr, uint>
~~~
{: #specaif title="Commonly used shape of a specific AIF"}


REST-specific Model {#rest-model}
-------------------

In the specific instantiation of the REST resources and the
permissions on them, for the object identifiers (`Toid`), we
use the URI of a resource on a CoAP server.  More specifically, since the
parts of the URI that identify the server ("authority" in
{{-uri}}) are what are authenticated during REST resource access ({{Section
4.2.2 of -http-semantics}} and {{Section 6.2 of RFC7252}}), they
naturally fall into the realm handled by the cryptographic armor; we therefore focus on
the "path" ("path-abempty") and "query" parts of the URI (*URI-local-part* in
this specification, as expressed by the Uri-Path and Uri-Query options
in CoAP).  As a consequence, AIF MUST be used in a way that it is
clear who is the target (enforcement point) of these authorizations
(note that there may be more than one target that the same
authorization applies to, e.g., in a situation with homogeneous
devices).

For the permissions (`Tperm`), we use a simple permissions model that
lists the subset of the REST (CoAP or HTTP) methods permitted.
This model is summarized in {{im-example}}.

| URI-local-part | Permission Set |
| /s/temp    | GET            |
| /a/led     | PUT, GET       |
| /dtls      | POST           |
{: #im-example title="An authorization instance in the AIF Information Model"}

In this example, a device offers a temperature sensor `/s/temp` for
read-only access, a LED actuator `/a/led` for read/write, and a
`/dtls` resource for POST access.

As will be seen in the data model ({{data-model}}), the representations
of REST methods provided are limited to those that have a CoAP method
number assigned; an extension to the model may be necessary to represent
permissions for exotic HTTP methods.

Limitations
-----------

This simple information model only allows granting permissions for
statically identifiable objects, e.g., URIs for the REST-specific
instantiation.  One might be tempted to extend the model towards URI
templates {{-uri-templates}} (for instance, to open up an
authorization for many parameter values as in
 `/s/temp{?any*}`).
However, that requires some considerations of
the ease and unambiguity of matching a given URI against a set of
templates in an AIF data item.

This simple information model also does not allow expressing
conditionalized access based on state outside the identification of
objects (e.g., "opening a door is allowed if that is not locked").

Finally, the model does not provide any special access for a set of
resources that are specific to a subject, e.g., that the subject
created itself by previous operations (PUT, POST, or PATCH/iPATCH {{-patch}}) or that were
specifically created for the subject by others.

REST-specific Model With Dynamic Resource Creation {#ext-rest-model}
----------------------------

The REST-specific Model With Dynamic Resource Creation addresses the
need to provide defined
access to dynamic resources that were created by the subject itself,
specifically, a resource that is made known to the subject by
providing Location-* options in a CoAP response or using the Location
header field in HTTP {{-http-semantics}} (the Location-indicating mechanisms).
(The concept is somewhat comparable to "ACL inheritance" in NFSv4
{{?RFC8881}}, except that it does not use a containment relationship
but the fact that the dynamic resource was created from a resource to
which the subject had access.)
In other words, it addresses an important subset of the third
limitation mentioned in {{limitations}}.

| URI-local-part | Permission Set                    |
| /a/make-coffee | POST, Dynamic-GET, Dynamic-DELETE |
{: #im-example-dynamic title="An authorization instance in the AIF Information Model With Dynamic Resource Creation"}

For a method X, the presence of a Dynamic-X permission means that the subject
holds permission to exercise the method X on resources that have been
returned in a 2.01 (201 Created) response by a Location-indicating mechanism to a request that the
subject made to the resource listed.
In the example shown in {{im-example-dynamic}}, POST operations on
`/a/make-coffee` might return the location of a resource dynamically
created on the coffee machine that allows GET to find
out about the status of, and DELETE to cancel, the coffee-making
operation.

Since the use of the extension defined in this section can be detected
by the mentioning of the Dynamic-X permissions, there is no need for
another explicit switch between the basic and the model extended by
dynamic resource creation; the
extended model is always presumed once a Dynamic-X permission is present.

Data Model
==========

Different data model specializations can be defined for the generic
information model given above.

In this section, we will give the data model for simple REST
authorization as per {{rest-model}} and {{ext-rest-model}}.
As discussed, in this case the object identifier is specialized as a text string
giving a relative URI (URI-local-part as absolute path on the server
serving as enforcement point).
The permission set is specialized to a single number `REST-method-set` by the following steps:

* The entries in the table that specify the same URI-local-part are merged
  into a single entry that specifies the union of the permission sets.
* The (non-dynamic) methods in the permission sets are converted into
  their CoAP method numbers, minus 1.
* Dynamic-X permissions are converted into what the number would have
  been for X, plus a Dynamic-Offset chosen as 32 (e.g., 35 is the
  number for Dynamic-DELETE as the number for DELETE is 3).
* The set of numbers is converted into a single number `REST-method-set` by taking two to the
  power of each (decremented) method number and computing the inclusive OR of the
  binary representations of all the power values.

This data model could be interchanged in the JSON
{{-json}} representation given in {{dm-json}}.

~~~json
[["/s/temp",1],["/a/led",5],["/dtls",2]]
~~~
{: #dm-json title="An authorization instance encoded in JSON (40 bytes)"}

In {{aif-cddl}}, a straightforward specification of the data model
(including both the methods from {{-coap}} and the new ones from
{{-patch}}, identified by the method code minus 1) is shown in CDDL
{{-cddl}} {{-cddlplus}}:

~~~~ cddl
AIF-REST = AIF-Generic<local-path, REST-method-set>
local-path = tstr   ; URI relative to enforcement point
REST-method-set = uint .bits methods
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

For the information shown in {{im-example}} and {{dm-json}}, a
representation in CBOR {{-cbor}} is given in {{dm-cbor}}; again,
several optimizations/improvements are possible.

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
values "URI-local-part" for `Toid` and "REST-method-set" for `Tperm`, as
per {{data-model}} of the present specification.

A specification that wants to use Generic AIF with different `Toid`
and/or `Tperm` is expected to request these as media type parameters
({{registries}}) and register a corresponding Content-Format ({{content-format}}).

IANA Considerations
===================

[^replace-xxxx]

[^replace-xxxx]: RFC Ed.: throughout this section, please replace RFC
      XXXX with the RFC number of this specification and remove this note.

Media Types
-----------

IANA is requested to add the following Media-Types to the "Media Types" registry.

| Name     | Template             | Reference                 |
| aif+cbor | application/aif+cbor | RFC XXXX, {{media-types}} |
| aif+json | application/aif+json | RFC XXXX, {{media-types}} |
{: align="left" title="New Media Types"}

For `application/aif+cbor`:

{: spacing="compact"}
Type name:
: application

Subtype name:
: aif+cbor

Required parameters:
: N/A

Optional parameters:
: * `Toid`: the identifier for the object for which permissions are
    supplied.
    A value from the media-type parameter sub-registry for `Toid`.
    Default value: "URI-local-part" (RFC XXXX).

  * `Tperm`: the data type of a permission set for the object
    identified via a `Toid`.
    A value from the media-type parameter sub-registry for `Tperm`.
    Default value: "REST-method-set" (RFC XXXX).

Encoding considerations:
: binary (CBOR)

Security considerations:
: {{seccons}} of RFC XXXX

Interoperability considerations:
: none

Published specification:
: {{media-types}} of RFC XXXX

Applications that use this media type:
: Applications that need to convey structured authorization data for
  identified resources, conveying sets of permissions.

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
: N/A

Optional parameters:
: * `Toid`: the identifier for the object for which permissions are
    supplied.
    A value from the media-type parameter sub-registry for `Toid`.
    Default value: "URI-local-part" (RFC XXXX).

  * `Tperm`: the data type of a permission set for the object
    identified via a `Toid`.
    A value from the media-type parameter sub-registry for `Tperm`.
    Default value: "REST-method-set" (RFC XXXX).

Encoding considerations:
: binary (JSON is UTF-8-encoded text)

Security considerations:
: {{seccons}} of RFC XXXX

Interoperability considerations:
: none

Published specification:
: {{media-types}} of RFC XXXX

Applications that use this media type:
: Applications that need to convey structured authorization data for
  identified resources, conveying sets of permissions.

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

For the media types application/aif+cbor and application/aif+json,
IANA is requested to create a sub-registry within
{{IANA.media-type-sub-parameters}} for the two media-type parameters
`Toid` and `Tperm`, populated with:

| Parameter | name            | Description/Specification       | Reference |
|-----------|-----------------|---------------------------------|-----------|
| Toid      | URI-local-part  | local-part of URI               | RFC XXXX  |
| Tperm     | REST-method-set | set of REST methods represented | RFC XXXX  |
{: align="left" title="New Media Type Parameters"}

The registration policy is Specification required {{-ianacons}}.
The designated expert will engage with the submitter to ascertain the
requirements of this document are addressed:

* The specifications for `Toid` and `Tperm` need to realize the
  general ideas of unambiguous object identifiers and permission lists
  in the context where the AIF data item is intended to be used, and
  their structure needs to be usable with the intended media types
  (application/aif+cbor and application/aif+json) as identified in the
  specification.

* The parameter names need to conform to {{Section 4.3 of
  -media-type-reg}}, but preferably are in {{KebabCase}} so they can
  easily be translated into names used in popular programming
  language APIs.

The designated experts will develop further criteria and guidelines as
needed.

Content-Format
--------------

IANA is requested to register Content-Format numbers in the "CoAP
Content-Formats" sub-registry, within the "Constrained RESTful
Environments (CoRE) Parameters" Registry {{IANA.core-parameters}}, as
follows:

| Content-Type         | Content Coding | ID   | Reference |
| application/aif+cbor | -              | TBD1 | RFC XXXX  |
| application/aif+json | -              | TBD2 | RFC XXXX  |
{: align="left" title="New Content-Formats"}

// RFC Ed.: please replace TBD1 and TBD2 with assigned IDs and remove this note.

In the registry as defined by {{Section 12.3 of -coap}} at the time of
writing, the column "Content-Type" is called "Media type" and the
column "Content Coding" is called "Encoding".

Note that applications that register `Toid` and `Tperm` values are
encouraged to also register Content-Formats for the relevant
combinations.


Security Considerations {#seccons}
=======================

The security considerations of {{-coap}} apply when AIF is used with
CoAP, and, if complex formats such as URIs are used for `Toid` or
`Tperm`, specifically {{Section 11.1 of -coap}}.
Some wider issues are discussed in {{-seccons}}.

When applying these formats, the referencing specification needs to be
careful to:

* ensure that the cryptographic armor employed around this format
  fulfills the referencing specification's security objectives, and that the armor or some
  additional information included in it with the AIF data item
  (1) unambiguously identifies the subject to which the authorizations
  shall apply and (2) provides any context information needed to derive the
  identity of the object to which authorization is being granted
  from the object identifiers (such as, for
  the data models defined in the present specification, the scheme and
  authority information that is used to construct the full URI), and

* ensure that the types used for `Toid` and `Tperm` provide the
  appropriate granularity and precision so that application requirements on the
  precision of the authorization information are fulfilled, and that
  all parties have the same understanding of each Toid/Tperm pair in
  terms of specified objects (resources) and operations on those.

For the data formats, the security considerations of {{-json}} and
{{-cbor}} apply.

A plain implementation of AIF might implement just the basic REST
model as per {{rest-model}}.  If it receives authorizations that
include permissions that use the REST-specific Model With Dynamic
Resource Creation {{ext-rest-model}}, it needs to either
reject the AIF data item entirely or act only on the
permissions that it does understand.
In other words, the semantics underlying an allow-list as discussed
above need to hold here as well.

An implementation of the REST-specific Model With Dynamic Resource
Creation {{ext-rest-model}} needs to carefully keep track of the
dynamically created objects and the subjects to which the Dynamic-X
permissions apply — both on the server side to enforce the permissions
and on the client side to know which permissions are available.

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
Many thanks also to the IESG reviewers, which provided several small
but significant observations.
{{{Benjamin Kaduk}}} provided an extensive review as responsible Area
Director, and indeed is responsible for much improvement in the document.

--- fluff

<!--  LocalWords:  cryptographically cryptographic strawman URI CoAP
 -->
<!--  LocalWords:  AIF unambiguity conditionalizing JSON CBOR
 -->
<!--  LocalWords:  optimizations instantiation conditionalized
 -->
