//! Hosts that are never intercepted, compiled in, in one group per source (see
//! [`BundledGroup`]).
//!
//! Sources, fetched 2026-09-25 (the first three) and 2026-09-30 (the rest, and the payment
//! service hosts added to Banks):
//! - Apple: every host in support.apple.com/101555, collapsed to `*.domain` where the
//!   article lists the whole domain or several of its hosts.
//! - AdGuard HttpsExclusions (github.com/AdguardTeam/HttpsExclusions) at commit
//!   a8eda6ecc184cc7000436302d64fb932d5205fe0 (2026-09-14): all of
//!   `exclusions/sensitive.txt`, the second-level `.com`, `.org` and `.net` domains of
//!   `exclusions/banks.txt`, and its entries for two payment services that apps embed,
//!   Google Pay and Braintree. With them, Braintree's client API host
//!   `api.braintreegateway.com`, which AdGuard does not list: the Braintree iOS SDK trusts
//!   only its own root certificates for both of its API hosts (braintree_ios at 440dd16,
//!   `BTHTTP.swift`). The rest of banks.txt (about 3,600 domains, mostly regional banks,
//!   1,439 of them German) is left to pin learning and the user list. AdGuard excludes each
//!   listed domain with its subdomains, so every entry becomes `*.domain`. Entries limited
//!   to a desktop app (`$app=`) are left out.
//! - Apps that refuse Tollgate's certificate without a TLS alert, confirmed in a device log.
//!   Such an app gives up in its own certificate check and closes the connection silently.
//!   Pin learning learns such a host only once the refusals repeat in several different
//!   seconds and nothing has trusted us for it lately, or once they flood it (see
//!   `Policy::record_silent_refusal`), so each of the app's hosts would fail a few times
//!   first, and none would be learned while the app refuses on many hosts at once.
//! - Microsoft Intune, Entra ID and Enterprise SSO plug-in hosts that Microsoft says must not
//!   be TLS-inspected. Most of them authenticate the device or the user with a client
//!   certificate, which an intercepting proxy cannot pass on. A server that asks for the
//!   certificate only optionally lets the handshake complete and fails the request later, as
//!   Intune's check-ins were observed to do through the proxy, so pin learning never learns
//!   it.
//! - Hosts that apps pin in their Info.plist: they fail every time they are intercepted.
//! - Apps that vendors of proxies and security products list as pinning, narrowed to their
//!   API or tenant domains.
//! - Hosts that pin learning learned in a device log, so that they do not fail again each
//!   time the learned pin expires.
//!
//! The comment at the head of each group names the sources of its entries. Each group is
//! sorted; a host listed in an earlier group is not repeated.

use std::sync::LazyLock;

/// One group of the bundled passthrough list, named by its source. The proxy passes every
/// group through alike; the groups exist for uses that need only some of them, such as
/// the DNS lists that must leave the hosts of sensitive services and banks unblocked. Only
/// `Sensitive` and `Banks` are exempt from those lists: a host they list under another
/// group is still blocked, and its `CONNECT` gets a `403`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BundledGroup {
    /// Apple services, from Apple's article on enterprise networks.
    Apple,
    /// AdGuard's `sensitive.txt`: identity, password managers, health, government and
    /// other services with sensitive personal information.
    Sensitive,
    /// AdGuard's `banks.txt`, its second-level `.com`, `.org` and `.net` domains: banks,
    /// card issuers, payment processors, brokers and exchanges; and its entries for Google
    /// Pay and Braintree, with Braintree's client API host.
    Banks,
    /// Apps that refuse Tollgate's certificate without a TLS alert.
    SilentRefusers,
    /// Device management and sign-in hosts that Microsoft says must not be TLS-inspected
    /// (Microsoft Intune, Entra ID and the Enterprise SSO plug-in), most of them since they
    /// take a client certificate.
    DeviceManagement,
    /// Hosts that apps pin in their Info.plist.
    DeclaredPins,
    /// Apps that vendors of proxies and security products list as pinning.
    ReportedPins,
    /// Hosts that pin learning learned in a device log.
    LearnedPins,
}

impl BundledGroup {
    /// Every group, in the order [`bundled_passthrough`] lists them.
    pub const ALL: [BundledGroup; 8] = [
        BundledGroup::Apple,
        BundledGroup::Sensitive,
        BundledGroup::Banks,
        BundledGroup::SilentRefusers,
        BundledGroup::DeviceManagement,
        BundledGroup::DeclaredPins,
        BundledGroup::ReportedPins,
        BundledGroup::LearnedPins,
    ];

    /// The group's patterns, in [`crate::HostPattern`] syntax, sorted.
    pub fn patterns(self) -> &'static [&'static str] {
        match self {
            BundledGroup::Apple => APPLE,
            BundledGroup::Sensitive => SENSITIVE,
            BundledGroup::Banks => BANKS,
            BundledGroup::SilentRefusers => SILENT_REFUSERS,
            BundledGroup::DeviceManagement => DEVICE_MANAGEMENT,
            BundledGroup::DeclaredPins => DECLARED_PINS,
            BundledGroup::ReportedPins => REPORTED_PINS,
            BundledGroup::LearnedPins => LEARNED_PINS,
        }
    }
}

/// The compiled-in passthrough patterns of every group, in [`crate::HostPattern`] syntax,
/// group after group in the order of [`BundledGroup::ALL`].
pub fn bundled_passthrough() -> &'static [&'static str] {
    static JOINED: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        BundledGroup::ALL
            .iter()
            .flat_map(|group| group.patterns().iter().copied())
            .collect()
    });
    JOINED.as_slice()
}

#[rustfmt::skip]
static APPLE: &[&str] = &[
    // Apple, support article 101555 "Use Apple products on enterprise networks"
    // (published 2026-08-07): Apple services fail when HTTPS is intercepted.
    "*.apple", "*.apple-cloudkit.com", "*.apple-dns.net", "*.apple-livephotoskit.com",
    "*.apple-mapkit.com", "*.apple.com", "*.appleschoolcontent.com", "*.apzones.com",
    "*.axm-usercontent-apple.com", "*.cdn-apple.com", "*.icloud-content.com", "*.icloud.com",
    "*.icloud.com.cn", "*.itunes.com", "*.mzstatic.com", "*.vertexsmb.com",
    "appldnld.apple.com.edgesuite.net", "apple-relay.cloudflare.com",
    "apple-relay.fastly-edge.com", "cp4.cloudflare.com", "crl3.digicert.com", "crl4.digicert.com",
    "ocsp.digicert.cn", "ocsp.digicert.com",
];

#[rustfmt::skip]
static SENSITIVE: &[&str] = &[
    // AdGuard HttpsExclusions exclusions/sensitive.txt: identity, password managers,
    // health, government and other services with sensitive personal information.
    "*.1177.se", "*.1password.ca", "*.1password.com", "*.1password.eu", "*.4user.yeskey.or.kr",
    "*.account.idocs.kz", "*.accounts.google.com", "*.accounts.kakao.com",
    "*.agenciatributaria.gob.es", "*.anaf.ro", "*.anonaddy.com", "*.app.deel.com",
    "*.app.traderepublic.com", "*.apps.cybonline.co.uk", "*.bbss.softbankbb.co.jp",
    "*.besoklegen.no", "*.binance.com", "*.bitwarden.com", "*.bitwarden.eu", "*.bolagsverket.se",
    "*.cable.auth.com", "*.cable.ua5v.com", "*.canadapost.ca", "*.cdn-secuchart.com",
    "*.cert.vno.co.kr", "*.certapi.yeskey.or.kr", "*.certcld.yeskey.or.kr", "*.certsign.ro",
    "*.cfg.smt.docomo.ne.jp", "*.checkout.bambora.com", "*.clave.gob.es", "*.cmbchina.com",
    "*.cnisnet.inss.gov.br", "*.completeid.com", "*.connect.auone.jp", "*.cra-arc.gc.ca",
    "*.dashlane.com", "*.dec.fazenda.df.gov.br", "*.digisign.ro", "*.diskstation.me",
    "*.dscloud.biz", "*.dscloud.me", "*.dscloud.mobi", "*.dsmynas.com", "*.dsmynas.org",
    "*.e-tjanster.1177.se", "*.ebs.ru", "*.ekb.esplus.ru", "*.enclave.ua5v.com", "*.enpass.io",
    "*.equifax.com", "*.experian.com", "*.f-cdn.com", "*.f-secure.com", "*.familyds.com",
    "*.familyds.net", "*.familyds.org", "*.fastmail.com", "*.fido.kt.com", "*.freelancer.ca",
    "*.freelancer.cl", "*.freelancer.cn", "*.freelancer.co.id", "*.freelancer.co.it",
    "*.freelancer.co.uk", "*.freelancer.com", "*.freelancer.com.au", "*.freelancer.com.bd",
    "*.freelancer.is", "*.freelancer.jp", "*.freelancer.ph", "*.freshbooks.com", "*.gate.io",
    "*.go.kr", "*.gorzdrav.spb.ru", "*.gosuslugi.ru", "*.gov.au", "*.gov.in", "*.gov.kr",
    "*.gov.pl", "*.gov.rs", "*.gov.ru", "*.gov.tw", "*.hanko.io", "*.home.mijngezondheid.net",
    "*.hotdoc.com.au", "*.hrblock.com", "*.i234.me", "*.id.biltema.com", "*.id.pilet.ee",
    "*.id.smt.docomo.ne.jp", "*.id.yandex.by", "*.id.yandex.com", "*.id.yandex.com.tr",
    "*.id.yandex.kz", "*.id.yandex.ru", "*.id.yandex.ua", "*.identity.idocs.kz",
    "*.identity.virginmedia.com", "*.idnotify.com", "*.idwatchdog.com", "*.inspectiamuncii.ro",
    "*.intelink.gov", "*.kashflow.com", "*.kau.gov.hu", "*.kauth.kakao.com", "*.kontur-ca.ru",
    "*.kronofogden.se", "*.kurlypay.co.kr", "*.lastpass.com", "*.lifelock.com",
    "*.lisa.motivtelecom.ru", "*.lk.billing74.ru", "*.lk.megafon.ru", "*.lk.sesb.ru",
    "*.lkk-ekb.esplus.ru", "*.login.kt.com", "*.login.live.com", "*.mail.tutanota.com",
    "*.mailbox.org", "*.mailfence.com", "*.meu.inss.gov.br", "*.mexc.com", "*.mijnpazio.nl",
    "*.mil", "*.mos.ru", "*.mvd.dor.ga.gov", "*.my.softbank.jp", "*.mydocomo.com", "*.myds.me",
    "*.myob.com", "*.navyfederal.org", "*.nid.naver.com", "*.nordpass.com",
    "*.nwdealer.megafon.ru", "*.ok.webhop.net", "*.onpointcu.com", "*.papara.com",
    "*.passport.yandex.by", "*.passport.yandex.com", "*.passport.yandex.com.tr",
    "*.passport.yandex.kz", "*.passport.yandex.ru", "*.passport.yandex.ua", "*.pay.naver.com",
    "*.paypal-topup.ee", "*.posteo.de", "*.prestigecu.org", "*.proton.me", "*.protonmail.ch",
    "*.protonmail.com", "*.protonvpn.com", "*.quickconnect.to", "*.raonsecure.co.kr",
    "*.raonsecure.com", "*.receiptbank.com", "*.receita.economia.gov.br", "*.roboform.com",
    "*.rzd.ru", "*.sdk.yeskey.or.kr", "*.secuchart.com", "*.securesafe.com", "*.seg-social.es",
    "*.signal-iduna.de", "*.simplelogin.io", "*.skatteverket.se", "*.sophos.com", "*.synology.me",
    "*.termius.com", "*.tikker.emta.ee", "*.transunion.com", "*.trbinance.com",
    "*.trueidentity.com", "*.trustedid.com", "*.turkiye.gov.tr", "*.tutanota.com",
    "*.uwzorgonline.nl", "*.vd.l.qq.com", "*.web.whatsapp.com", "*.websign.ro",
    "*.workflow.idocs.kz", "*.xero.com", "*.zakupki.gov.ru",
];

#[rustfmt::skip]
static BANKS: &[&str] = &[
    // AdGuard HttpsExclusions exclusions/banks.txt: second-level .com, .org and .net
    // domains (banks, card issuers, payment processors, brokers, exchanges). From its other
    // entries, those of two payment services that apps embed: Google Pay (pay.google.com)
    // and Braintree (payments.braintree-api.com). And Braintree's client API host
    // api.braintreegateway.com, which AdGuard does not list: in braintree_ios at 440dd16,
    // BTHTTP.swift makes the SDK's own root certificates the only anchors and rejects the
    // server otherwise, for this host (TokenizationKey.swift) as for the other.
    // It is one host, since client-analytics.braintreegateway.com is a tracker. Checked on
    // 2026-09-30: with these entries the exempting DNS lists leave out the same 137 blocks
    // as before.
    "*.1stnorcalcu.org", "*.2checkout.com", "*.53.com", "*.abanca.com", "*.abchina.com",
    "*.accessbankplc.com", "*.acledabank-internetbanking.com", "*.acorns.com",
    "*.acs-education.com", "*.adelfibanking.com", "*.adyen.com", "*.agranisme.org", "*.akbank.com",
    "*.alahli.com", "*.alawwalbank.com", "*.alinma.com", "*.alipay.com", "*.allegacy.org",
    "*.alliantcreditunion.com", "*.alliantcreditunion.org", "*.ally.com", "*.altbank.com",
    "*.amedigital.com", "*.amerantbank.com", "*.americanexpress.com", "*.amundi-tc.com",
    "*.anz.com", "*.apsiyon.com", "*.atabank.com", "*.auxmoney.com", "*.avangate.com",
    "*.axisbank.com", "*.bancnetonline.com", "*.bancoactivo.com", "*.bancocajasocial.com",
    "*.bancodebogota.com", "*.bancoexterior.com", "*.bancofinandina.com", "*.bancoldex.com",
    "*.bancomer.com", "*.bancrecerdigital.com", "*.bancsabadell.com", "*.banesconline.com",
    "*.bangkokbank.com", "*.bankalbilad.com", "*.bankchb.com", "*.bankcomm.com", "*.bankinter.com",
    "*.bankofamerica.com", "*.bankofbaku.com", "*.bankofbeirut.com", "*.banorte.com",
    "*.banplusonline.com", "*.barclaycardus.com", "*.bbacbank.com", "*.bcblbd.com", "*.bcu.org",
    "*.becu.org", "*.betterment.com", "*.bhf-bank.com", "*.bidv.com", "*.bil.com",
    "*.billdesk.com", "*.bitfinex.com", "*.bitget.com", "*.bitpanda.com", "*.bitso.com",
    "*.bitstamp.net", "*.bittrex.com", "*.bitwala.com", "*.bity.com", "*.blockfi.com",
    "*.blombank.com", "*.bmo.com", "*.bmoharris.com", "*.bnpparibas.com", "*.bobibanking.com",
    "*.bochk.com", "*.boursobank.com", "*.bpcprocessing.com", "*.bpiexpressonline.com",
    "*.btc-e.com", "*.btgpactual.com", "*.btpn.com", "*.bunq.com", "*.bybit.com",
    "*.caixa-enginyers.com", "*.campuscu.com", "*.capfed.com", "*.capitalone.com", "*.cardpay.com",
    "*.cbcfcu.org", "*.ccb.com", "*.ccservicing.com", "*.changelly.com", "*.chase.com",
    "*.chime.com", "*.chinatrust.com", "*.cibc.com", "*.citi.com", "*.citibankonline.com",
    "*.citizensbank.com", "*.citizensbankonline.com", "*.citybankplc.com", "*.cnb.com",
    "*.coastal24.com", "*.coastalbank.com", "*.coastcapitalsavings.com", "*.cobinhood.com",
    "*.coinbase.com", "*.colpatria.com", "*.combankdigital.com", "*.commerzfinanz.com",
    "*.computershare.com", "*.copayco.com", "*.credit-suisse.com", "*.creditbank.com",
    "*.creditdnepr.com", "*.creditonebank.com", "*.criptointercambio.com", "*.ctbcbank.com",
    "*.currency.com", "*.danamonline.com", "*.danskebank.com", "*.davivienda.com", "*.db.com",
    "*.dcu-online.org", "*.dcu.org", "*.desjardins.com", "*.devbnkphl.com", "*.dhakabankltd.com",
    "*.dhbbank.com", "*.directnet.com", "*.discover.com", "*.docfcu.org", "*.dutchbanglabank.com",
    "*.dvbbank.com", "*.e-bankofbaku.com", "*.eastwestbanker.com", "*.ebase.com", "*.ecommpay.com",
    "*.elevationsbanking.com", "*.elevationscu.com", "*.ellisbank.com", "*.emiratesnbd.com",
    "*.enpara.com", "*.etrade.com", "*.eurobank-ua.com", "*.evobanco.com", "*.fairfx.com",
    "*.farmersebank.com", "*.fastbill.com", "*.fbtonline.com", "*.fbtonline.net", "*.fbwebpos.com",
    "*.fednetbank.com", "*.feniciabank.com", "*.fidelity.com", "*.finansonline.com",
    "*.finecobank.com", "*.firstbankcard.com", "*.firsttechfed.com", "*.fnbba.com",
    "*.fosterswiss.com", "*.frostbank.com", "*.fsibplc.com", "*.ftx.com", "*.fubon.com",
    "*.getpenta.com", "*.globalhbl.com", "*.greensill-bank.com", "*.grenke.net",
    "*.grenkeonline.com", "*.growfinancial.org", "*.grupobancolombia.com", "*.gtbank.com",
    "*.gunaybank.com", "*.hanabank.com", "*.hangseng.com", "*.harrisbank.com", "*.hdfcbank.com",
    "*.hellenicnetbanking.com", "*.hellostake.com", "*.hitbtc.com", "*.hlebroking.com",
    "*.holvi.com", "*.hsbc.com", "*.hsbcnet.com", "*.hsbcprivatebank.com", "*.hubank.com",
    "*.huntington.com", "*.ibanking-services.com", "*.icicibank.com", "*.icon25-bank.com",
    "*.idbi.com", "*.idbibank.com", "*.independentreserve.com", "*.inetpayonline.com",
    "*.ingonline.com", "*.ingwb.com", "*.inicis.com", "*.instamojo.com",
    "*.interactivebrokers.com", "*.internetpanin.com", "*.intesasanpaolo.com", "*.jago.com",
    "*.jenius.com", "*.jkopay.com", "*.juliusbaer.com", "*.kbstar.com", "*.kebhana.com",
    "*.key.com", "*.kgibank.com", "*.klarna.com", "*.klikbca.com", "*.kokobank.com",
    "*.kontist.com", "*.kraken.com", "*.kreditprombank.com", "*.krungsri.com",
    "*.krungsribizonline.com", "*.krungsrionline.com", "*.ktbnetbank.com", "*.kucoin.com",
    "*.leboutique.com", "*.legalandgeneral.com", "*.leomoney.com", "*.lgbbank.com", "*.liqpay.com",
    "*.lloydsbank.com", "*.localbitcoins.com", "*.localethereum.com", "*.lzo.com",
    "*.m1finance.com", "*.marcus.com", "*.marinecu.com", "*.maritimebank.com",
    "*.master-capital.org", "*.masterpass.com", "*.mctcu.org", "*.meabank.com", "*.mebytmb.com",
    "*.megabank.net", "*.memberdirect.net", "*.mercantilbanco.com", "*.metzler.com",
    "*.midoregon.com", "*.mitfcu.org", "*.ml.com", "*.mobikwik.com", "*.modhumotibankltd.com",
    "*.mohela.com", "*.monese.com", "*.monzo.com", "*.mtochka.com", "*.myetherwallet.com",
    "*.myfedloan.org", "*.mymerrill.com", "*.myoccu.org", "*.myvoba.com", "*.n26.com",
    "*.natwest.com", "*.neteller.com", "*.netpnb.com", "*.netteller.com", "*.nonghyup.com",
    "*.nordea.com", "*.nsandi.com", "*.nwolb.com", "*.o-bank.com", "*.oddo-bhf.com",
    "*.oneaccount.com", "*.onfastspring.com", "*.onlinebanking-ibb-ag.com", "*.optumbank.com",
    "*.oregonstatecu.com", "*.oschad24.com", "*.pagbrasil.com", "*.palmettohealthcu.org",
    "*.pay.google.com", "*.payco.com", "*.payeer.com", "*.paykun.com",
    "*.payments.braintree-api.com", "*.payonlinesystem.com", "*.paypal-nakit.com",
    "*.paypal.com", "*.paypalobjects.com", "*.payproglobal.com", "*.paytm.com", "*.paytr.com",
    "*.payture.com", "*.pbbdirekt.com", "*.pbebank.com", "*.pcbac.com", "*.pearler.com",
    "*.penfed.org", "*.picpay.com", "*.pictet.com", "*.piraeusbank.com", "*.plategka.com",
    "*.plimus.com", "*.pnc.com", "*.pocketsmith.com", "*.portaldepagosmercantil.com",
    "*.priovtb.com", "*.privatbank1891.com", "*.prosperitybankusa.com", "*.pxpayplus.com",
    "*.qantas.com", "*.qantasmoney.com", "*.qiwi.com", "*.qnb.com", "*.qnbfinansbank.com",
    "*.questrade.com", "*.razorpay.com", "*.rbcroyalbank.com", "*.rblbank.com", "*.rbsdigital.com",
    "*.rbsinternational.com", "*.rcbconline-corporate.com", "*.rcbconlinebanking.com",
    "*.rcuonline.org", "*.redwoodcu.org", "*.revolut.com", "*.rfcu.com", "*.riyadbank.com",
    "*.robinhood.com", "*.rusnarbank.com", "*.russobank.com", "*.sabb.com", "*.saferpay.com",
    "*.samba.com", "*.sampathvishwa.com", "*.samsungpop.com", "*.santanderbank.com",
    "*.sberbank.com", "*.sbicard.com", "*.sbiepay.com", "*.sc.com", "*.scbeasy.com",
    "*.schwab.com", "*.scotiabank.com", "*.secureinternetbank.com", "*.securitybank.com",
    "*.selco.org", "*.sendwyre.com", "*.settrade.com", "*.sharesight.com", "*.shinhan.com",
    "*.shinseibank.com", "*.signicat.com", "*.simple.com", "*.simplii.com", "*.sinopac.com",
    "*.smbc-card.com", "*.societegenerale.com", "*.sorexpay.com", "*.southindianbank.com",
    "*.spectrocoin.com", "*.sslcommerz.com", "*.stanbicibtcbank.com", "*.starlingbank.com",
    "*.start2pay.com", "*.stripe.com", "*.suncoast.com", "*.td.com", "*.tdameritrade.com",
    "*.tdbank.com", "*.tdcanadatrust.com", "*.tescobank.com", "*.theinstapay.com",
    "*.theworldexchange.net", "*.tiaa.org", "*.tiscoasset.com", "*.titanvest.com",
    "*.tmbdirect.com", "*.tochka.com", "*.tossbank.com", "*.tossinvest.com", "*.touchbank.com",
    "*.traderepublic.com", "*.transaccionesbancolombia.com", "*.transamerica.com",
    "*.traviscu.org", "*.ubinco.com", "*.ubs.com", "*.uiccu.org", "*.ukrgasbank.com",
    "*.ukrsibbank.com", "*.umcu.org", "*.unicreditbanking.net", "*.unionbank.com",
    "*.unionbankph.com", "*.univest.net", "*.uphold.com", "*.upma.org", "*.usaa.com",
    "*.vakifbankusa.com", "*.vancity.com", "*.vanguard.com", "*.venmo.com", "*.veridiancu.org",
    "*.virginmoney.com", "*.vystarcu.org", "*.wayforpay.com", "*.wealthbar.com",
    "*.wealthfront.com", "*.wealthsimple.com", "*.webbankir.com", "*.wellsfargo.com",
    "*.westconsincu.org", "*.wideup.net", "*.wise.com", "*.wlp-acs.com", "*.wmtransfer.com",
    "*.wooppay.com", "*.wooribank.com", "*.xtb.com", "*.yesrewardz.com", "*.youneedabudget.com",
    "*.zaim.com", "api.braintreegateway.com",
];

#[rustfmt::skip]
static SILENT_REFUSERS: &[&str] = &[
    // X (formerly Twitter), iOS app com.atebits.Tweetie2 12.29 on iOS 27.0.1, device log of
    // 2026-09-30: every intercepted API connection was cancelled in the app's certificate
    // check ("Cancelled during verify block", task error -999), without a TLS alert.
    "*.twimg.com", "*.twitter.com", "*.x.com",
];

#[rustfmt::skip]
static DEVICE_MANAGEMENT: &[&str] = &[
    // Microsoft Intune (learn.microsoft.com/intune/fundamentals/endpoints, ms.date
    // 2026-08-21): SSL inspection "isn't supported for '*.manage.microsoft.com',
    // '*.dm.microsoft.com'". Intune check-ins were observed failing through the proxy on
    // 2026-09-30: each MDM check-in to i.manage.microsoft.com completed its handshake with
    // Tollgate's certificate, was redirected to /EnrollmentServer/CertificateFallback.aspx
    // and failed with a 404 ("Could not send response to MDM server").
    // Microsoft Entra ID (MicrosoftDocs/entra-docs at 95d306db), to be kept out of TLS
    // inspection for client certificate authentication: device registration
    // (enterpriseregistration.windows.net and certauth. under it, plan-device-deployment.md),
    // hybrid join (device.login.microsoftonline.com, how-to-hybrid-join.md) and
    // certificate-based sign-in (*.certauth.login.microsoftonline.com,
    // concept-certificate-based-authentication-technical-deep-dive.md). And the Enterprise SSO
    // plug-in's configuration service config.edge.skype.com, among the URLs to exclude from
    // TLS break-and-inspect (entra-docs at a4be4ac4, apple-sso-plugin.md).
    "*.certauth.login.microsoftonline.com", "*.dm.microsoft.com",
    "*.enterpriseregistration.windows.net", "*.manage.microsoft.com", "config.edge.skype.com",
    "device.login.microsoftonline.com",
];

#[rustfmt::skip]
static DECLARED_PINS: &[&str] = &[
    // Pins that apps declare in their Info.plist, read on 2026-09-30. Jira 264.0.0:
    // NSPinnedDomains, which iOS enforces, for its production hosts (atlassian-isolated.net
    // with its subdomains, the others without). Staging hosts are left out.
    "*.atlassian-isolated.net", "api-private.atlassian.com", "api.atlassian.com",
    "api.media.atlassian.com", "auth.atlassian.com", "media-cdn.atlassian.com",
];

#[rustfmt::skip]
static REPORTED_PINS: &[&str] = &[
    // Apps that vendors list as pinning; none ran in a device log. Netskope's list of
    // certificate-pinned applications
    // (docs.netskope.com/en/certificate-pinned-applications, 2026-09-30): Eventbrite and
    // Workday on iOS, narrowed to Eventbrite's API domain and to Workday's tenant domain
    // myworkday.com, one of the app's associated domains. WhatsApp: Proxyman's
    // troubleshooting page names it among the apps protected by SSL pinning on iOS, and
    // AdGuard HttpsExclusions (at a8eda6ec) android.txt excludes whatsapp.net for the Android
    // WhatsApp app among the apps known to pin (AdguardForAndroid#3052). The hosts the DNS
    // lists block under these domains (dit. and privatestats.whatsapp.net) still get a 403
    // for their CONNECT, which with Connectivity Assist on a browser can retry over cellular
    // (a WhatsApp Web script reports to dit.); the app, reported to pin, would fail a
    // blocked connection's handshake the same way. Narrowing the pattern to the media hosts
    // would instead intercept the app's other hosts, whose pins nothing has ruled out.
    "*.eventbriteapi.com", "*.myworkday.com", "*.whatsapp.net",
];

#[rustfmt::skip]
static LEARNED_PINS: &[&str] = &[
    // Device log of 2026-09-30: "learned certificate pin for
    // meta-ohttp-relay-prod.fastly-edge.com after UnknownCa". Meta's OHTTP relay, run by
    // Fastly, carries only requests encrypted to Meta's gateway, so passing it through
    // loses no filtering.
    "meta-ohttp-relay-prod.fastly-edge.com",
];
