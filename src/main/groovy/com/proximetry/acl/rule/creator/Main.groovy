import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.proximetry.acl.objects.Attribute
import com.proximetry.acl.objects.Condition
import com.proximetry.acl.objects.Policy
import com.proximetry.acl.objects.PolicyResource
import com.proximetry.acl.objects.PolicySubject
import com.proximetry.acl.objects.Target
import com.proximetry.asstorage.api.enums.ACLDecisionStatus
import groovy.json.JsonBuilder
import groovy.util.logging.Slf4j
import org.apache.poi.ss.usermodel.*
import org.apache.poi.xssf.usermodel.XSSFSheet
import org.apache.poi.xssf.usermodel.XSSFWorkbook

@Slf4j
class Main {
    String ADMIN = "Admin"
    String ALL = "All"
    def ALL_ROLE_DEFINITION = ["Operator", "Technician"]

    public static void main(String[] args) {
        System.out.println("CSV formatter to ACLPolicies")
        if (args.length < 1) {
            throw new Exception("set file name");
        }
        String filename = args[0]
        Main m = new Main()
        m.convertCsvToAclPolicy(filename)
    }

    void convertCsvToAclPolicy(String filename) {
        File csvData = new File(filename);
        if (!csvData.exists()) {
            throw new Exception(String.format("File %s does not exists", csvData.getAbsoluteFile()));
        }
        if (!csvData.isFile()) {
            throw new Exception(String.format("%s is not a file", csvData.getAbsoluteFile()));
        }
        def rules = readCsvFile(csvData)
        log.info("found {} rules ", rules.size())
        //def allRoles = findAllRoles(rules)
        def policies = convertXlsRulesToPolicies(rules);
        def aclPolicyFile = new File(csvData.parentFile, "aclPolicy.json");
        AclPolicy policy = new AclPolicy(policies);
        saveAclPolicy(aclPolicyFile, policy)
    }

    void saveAclPolicy(File file, AclPolicy policy) {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        file.withWriter('UTF-8') { writer ->
            writer.write(gson.toJson(policy))
        }
    }

    def extractRoles(String roleField) {
        roleField.tokenize(',')
    }

    def convertXlsRulesToPolicies(List list) {
        def policies = []
        policies.add(createAdminPermitToAllResources())
        list.each { rule ->
            def rulePolicies = convertRuleToPolicies(rule)
            if (rulePolicies.size > 0) {
                policies.addAll(rulePolicies)
            }
        }
        policies.add(createDenyAll())
        policies
    }

    def createDenyAll() {
        Policy denyAll = new Policy()
        denyAll.name = "Deny all operations for unknown users"
        denyAll.effect = ACLDecisionStatus.DENY
        denyAll
    }

    def convertRuleToPolicies(XlsRule o) {
        List<String> xlsRoles = extractRoles(o.roles)

        List<String> rolesOtherThanAdmin = xlsRoles.findAll({ !it.equals(ADMIN) })
        def policySet = []
        rolesOtherThanAdmin.each { it ->
            if (it.equals(ALL)) {
                ALL_ROLE_DEFINITION.each { role ->
                    policySet.add(createPolicy(o.method, o.path, role, ACLDecisionStatus.PERMIT))
                }
            } else {
                policySet.add(createPolicy(o.method, o.path, it, ACLDecisionStatus.PERMIT))
            }
        }
        policySet
    }

    def createPolicy(String method, String resource, String role, ACLDecisionStatus effect) {
        Policy p = new Policy()
        p.name = effect.name() + '-' + role + '-' + method + '-to-' + resource
        p.effect = effect
        p.target = createTarget(method, resource)
        p.conditions = [conditionSingleRole(role)]
        p
    }

    Target createTarget(String action, String resource) {
        Target t = new Target()
        t.resource = createResource(resource)
        t.action = action
        t.subject = createSubject()
        t
    }

    PolicySubject createSubject() {
        PolicySubject ps = new PolicySubject()
        ps.name = "Has a role"
        ps.attributes = [createAttribute("role")]
        ps
    }

    Attribute createAttribute(String s) {
        Attribute a = new Attribute()
        a.name = s
        a
    }

    PolicyResource createResource(String resource) {
        PolicyResource pr = new PolicyResource()
        pr.name = resourcePathName(resource)
        pr.uriTemplate = resource;
        pr
    }

    def resourcePathName(String resource) {
        def splitted = resource.tokenize("/")
        splitted[0]
    }

    def createAdminPermitToAllResources() {
        Policy p = new Policy()
        p.effect = ACLDecisionStatus.PERMIT
        p.name = 'PERMIT-' + ADMIN + '-All';
        //p.target - not defined - for all resources
        p.conditions = [conditionSingleRole(ADMIN)]
        p
    }

    Condition conditionSingleRole(String s) {
        Condition c = new Condition();
        c.name = "Has a " + s + " role"
        c.condition = "match.single(subject.attributes('https://acs.attributes.int', 'role'),'" + s + "')"
        c
    }

    def readCsvFile(File file) {
        FileInputStream excelFile = new FileInputStream(file);
        XSSFWorkbook workbook = new XSSFWorkbook(excelFile);
        XSSFSheet datatypeSheet = workbook.getSheetAt(0);
        def rules = []
        Iterator<Row> rowIt = datatypeSheet.iterator()
        while (rowIt.hasNext()) {
            Row row = rowIt.next()
            if (row.getRowNum() > 0) {
                rules.add(new XlsRule(
                        row.getCell(0).getStringCellValue(),
                        row.getCell(1).getStringCellValue(),
                        (row.getCell(2) != null) ? row.getCell(2).getStringCellValue() : ALL))

            }
        }
        rules
    }

    public class XlsRule {
        String method
        String path
        String roles

        public XlsRule(String method, String path, String roles) {
            this.method = method;
            this.path = path;
            this.roles = roles;
        }
    }

    public class AclPolicy {
        String name = "DEFAULT ACL POLICY";
        List<Policy> policies;

        public AclPolicy(List<Policy> policies) {
            this.policies = policies
        }
    }
}
