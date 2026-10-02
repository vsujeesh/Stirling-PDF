package stirling.software.proprietary.security.configuration.ee;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static stirling.software.proprietary.security.configuration.ee.KeygenLicenseVerifier.License;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import stirling.software.common.model.ApplicationProperties;
import stirling.software.proprietary.service.UserLicenseSettingsService;

@ExtendWith(MockitoExtension.class)
class LicenseKeyCheckerTest {

    @Mock private KeygenLicenseVerifier verifier;
    @Mock private UserLicenseSettingsService userLicenseSettingsService;

    @Test
    void bootGateRefreshesTeamBeforeRejectingPaidConfiguration() {
        ApplicationProperties properties = new ApplicationProperties();
        properties.getPremium().setEnabled(true);
        properties.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers())
                .thenThrow(new IllegalStateException("Database not initialized"))
                .thenReturn(300);
        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, properties, userLicenseSettingsService);
        checker.init();
        // The key verifies NORMAL, but the first Team read fails, leaving the field's ENTERPRISE
        // default in place.
        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());
        assertThatCode(() -> checker.requireProOrEnterprise("storage.provider=s3"))
                .doesNotThrowAnyException();
        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
        // The gate never re-verifies the key; only the initial read did.
        verify(verifier).verifyLicense("free");
    }

    @Test
    void premiumDisabled_fallsBackToEnterprise() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(false);
        props.getPremium().setKey("dummy");

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());
        verifyNoInteractions(verifier);
    }

    @Test
    void directKey_verified() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("abc");
        when(verifier.verifyLicense("abc")).thenReturn(License.SERVER);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
        verify(verifier).verifyLicense("abc");
    }

    @Test
    void fileKey_verified(@TempDir Path temp) throws IOException {
        Path file = temp.resolve("license.txt");
        Files.writeString(file, "filekey");

        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("file:" + file);
        when(verifier.verifyLicense("filekey")).thenReturn(License.ENTERPRISE);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());
        verify(verifier).verifyLicense("filekey");
    }

    @Test
    void missingFile_fallsBackToEnterprise(@TempDir Path temp) {
        Path file = temp.resolve("missing.txt");
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("file:" + file);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());
        verifyNoInteractions(verifier);
    }

    // ----- requireProOrEnterprise: shared boot-time gate for premium features -----

    @Test
    void requireProOrEnterprise_normalLicense_throwsWithFeatureName() {
        LicenseKeyChecker checker = checkerWithLicense(License.NORMAL);
        assertThatThrownBy(() -> checker.requireProOrEnterprise("storage.provider=s3"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("storage.provider=s3 requires a Pro or Enterprise license");
    }

    @Test
    void requireProOrEnterprise_serverLicense_passes() {
        LicenseKeyChecker checker = checkerWithLicense(License.SERVER);
        assertThatCode(() -> checker.requireProOrEnterprise("any.feature=true"))
                .doesNotThrowAnyException();
    }

    @Test
    void requireProOrEnterprise_enterpriseLicense_passes() {
        LicenseKeyChecker checker = checkerWithLicense(License.ENTERPRISE);
        assertThatCode(() -> checker.requireProOrEnterprise("any.feature=true"))
                .doesNotThrowAnyException();
    }

    /**
     * The single injection point for cloud-sold Team. A Team-only buyer installs no key, so their
     * keyless tier is already ENTERPRISE; the promotion matters for an installed key that verifies
     * NORMAL, which the Team capacity then lifts to SERVER. Every licence consumer reads
     * getPremiumLicenseEnabledResult(), so promoting that one field is what lights them up; the
     * tests below pin the boundaries the promotion must not cross.
     */
    @Test
    void teamPlan_promotesToServerOverANormalKey() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(100);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
        // The key granted nothing, which is what keeps the seat arithmetic off premium.maxUsers.
        assertEquals(License.NORMAL, checker.getLicenseKeyResult());
        verify(verifier).verifyLicense("free");
    }

    /**
     * A NORMAL-verifying key is the only path that reaches the Team read: a keyless install is
     * ENTERPRISE and returns before the promotion is consulted.
     */
    @Test
    void teamPlan_promotesANormalVerifyingKey() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(100);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
    }

    /**
     * Enterprise is contracted and stays licence-only, so runningEE and every @EnterpriseEndpoint
     * keep requiring a real key however much capacity the cloud team bought.
     */
    @Test
    void teamPlan_neverPromotesToEnterprise() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(100000);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
    }

    /** Precedence is an OR: a licence that already grants more is not lowered to SERVER. */
    @Test
    void enterpriseLicence_outranksTheTeamPlan() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("ent");
        when(verifier.verifyLicense("ent")).thenReturn(License.ENTERPRISE);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());
        // The holding is not even consulted once the key already grants more.
        verify(userLicenseSettingsService, never()).refreshLinkedTeamUsers();
    }

    @Test
    void noTeamPlan_staysNormal() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(null);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        assertEquals(License.NORMAL, checker.getPremiumLicenseEnabledResult());
    }

    /**
     * init() is a @PostConstruct, so it runs long before the datasource exists. The row read
     * therefore throws rather than answering, and boot has to survive it -- the promotion is the
     * tier beans' job, not this one's. The failed read leaves the field's ENTERPRISE default.
     */
    @Test
    void unreadableHolding_doesNotBreakBoot() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers())
                .thenThrow(new IllegalStateException("no datasource yet"));

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);

        assertThatCode(checker::init).doesNotThrowAnyException();
        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());
    }

    /** ApplicationReadyEvent is the backstop for an instance whose row was unreadable earlier. */
    @Test
    void applicationReady_appliesThePromotionTheBootReadCouldNotSee() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers())
                .thenThrow(new IllegalStateException("no datasource yet"))
                .thenReturn(100);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();
        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());

        checker.onApplicationReady();

        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
        verify(userLicenseSettingsService).updateLicenseMaxUsers();
    }

    /**
     * The seam between the daily sync and the tier. The sync refreshes the entitlement for its own
     * reasons and says so; nothing re-read the plan on the back of it, which is how a purchase
     * could sit unnoticed until the weekly Keygen recheck.
     */
    @Test
    void entitlementRefresh_promotesWithoutWaitingForTheLicenceRecheck() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        // Unreadable at boot, as it is on a real start: no datasource yet.
        when(userLicenseSettingsService.refreshLinkedTeamUsers())
                .thenThrow(new IllegalStateException("no datasource"));

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();
        assertEquals(License.ENTERPRISE, checker.getPremiumLicenseEnabledResult());

        // What the sync's event stands for: the plan is now readable and says 100 users.
        reset(userLicenseSettingsService);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(100);
        checker.onEntitlementRefreshed();

        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
        // Still no second Keygen round trip: the whole point is that this is the cheap path.
        verify(verifier).verifyLicense("free");
    }

    /** A cancellation travels the same seam, and must not need a restart either. */
    @Test
    void entitlementRefresh_demotesWhenThePlanIsGone() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(100);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();
        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());

        reset(userLicenseSettingsService);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(null);
        checker.onEntitlementRefreshed();

        assertEquals(License.NORMAL, checker.getPremiumLicenseEnabledResult());
    }

    /** A read that throws leaves the tier where it was rather than silently demoting a payer. */
    @Test
    void entitlementRefresh_keepsTheTierWhenTheReadFails() {
        ApplicationProperties props = new ApplicationProperties();
        props.getPremium().setEnabled(true);
        props.getPremium().setKey("free");
        when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
        when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(100);

        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();

        reset(userLicenseSettingsService);
        when(userLicenseSettingsService.refreshLinkedTeamUsers())
                .thenThrow(new IllegalStateException("SaaS unreachable"));
        checker.onEntitlementRefreshed();

        assertEquals(License.SERVER, checker.getPremiumLicenseEnabledResult());
    }

    private LicenseKeyChecker checkerWithLicense(License level) {
        ApplicationProperties props = new ApplicationProperties();
        if (level == License.NORMAL) {
            props.getPremium().setEnabled(true);
            props.getPremium().setKey("free");
            when(verifier.verifyLicense("free")).thenReturn(License.NORMAL);
            when(userLicenseSettingsService.refreshLinkedTeamUsers()).thenReturn(null);
        } else {
            props.getPremium().setEnabled(true);
            props.getPremium().setKey("any");
            when(verifier.verifyLicense("any")).thenReturn(level);
        }
        LicenseKeyChecker checker =
                new LicenseKeyChecker(verifier, props, userLicenseSettingsService);
        checker.init();
        return checker;
    }
}
